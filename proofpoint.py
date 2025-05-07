import requests
import json
import pandas as pd
from time import sleep
from urllib.parse import unquote, urlparse, parse_qs

def get_phishing_data(region, api_key, filters=None, page_number=None, page_size=None):
    campaign_results = []
    base_url = f"https://results.{region}.securityeducation.com/api/reporting/v0.3.0/phishing"
    headers = {"x-apikey-token": api_key}
    params = {}

    if filters:
        for key, value in filters.items():
            params[f"filter[{key}]"] = value
    if page_number is not None:
        params["page[number]"] = page_number
    if page_size is not None:
        params["page[size]"] = page_size

    max_retries = 5
    retry_count = 0

    while retry_count <= max_retries:
        try:
            response = requests.get(base_url, headers=headers, params=params)
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 60))
                print(f"Rate limited. Waiting {retry_after} seconds before retrying...")
                sleep(retry_after)
                retry_count += 1
                continue

            response.raise_for_status()
            response_dict = response.json()

            if isinstance(response_dict["data"], list):campaign_results.extend(response_dict["data"])

            url_query = unquote(urlparse(response_dict["links"]["last"]).query)
            parsed_query = parse_qs(url_query)
            page_numbers = parsed_query.get('page[number]')[0]
            print(f"Page {response_dict['meta']['page_number']} of {page_numbers} downloaded")

            is_next = response_dict["links"]["next"]
            while is_next:
                sleep(1)
                next_url = f"https://results.{region}.securityeducation.com{is_next}"
                response = requests.get(next_url, headers=headers)

                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 60))
                    print(f"Rate limited during pagination. Waiting {retry_after} seconds...")
                    sleep(retry_after)
                    continue

                response.raise_for_status()
                response_dict = response.json()
                print(f"Page {response_dict['meta']['page_number']} of {page_numbers} downloaded")
                if isinstance(response_dict["data"], list):
                    campaign_results.extend(response_dict["data"])
                is_next = response_dict["links"].get("next", False)

            return campaign_results

        except requests.exceptions.RequestException as e:
            print(f"Error fetching data: {e}")
            if retry_count < max_retries:
                wait_time = 2 ** retry_count
                print(f"Retrying in {wait_time} seconds...")
                sleep(wait_time)
                retry_count += 1
            else:
                print("Max retries reached. Giving up.")
                break
    return None

def save_transposed_csv(data, filename, campaign_status_list):
    if not data:
        print(f"No data to process for {filename}")
        return

    user_id_cols = ["userfirstname", "userlastname", "useremailaddress"]
    event_col = "eventtype"
    extra_fields = ["campaignname", "senttimestamp", "eventtimestamp", "campaignstartdate", "sso_id"]
    all_fields = user_id_cols + [event_col] + extra_fields

 
    full_df = pd.DataFrame([{k: item["attributes"].get(k) for k in all_fields} for item in data])

    # Count only eventtimestamp rows that match allowed event types
    count_df = (full_df[(full_df[event_col].isin(campaign_status_list)) &(full_df["eventtimestamp"].notna())].groupby(user_id_cols)["eventtimestamp"].count().reset_index(name="multi email open"))

    # Filter for pivot and metadata
    filtered_df = full_df[full_df[event_col].isin(campaign_status_list)].copy()
    filtered_df["value"] = True

    # Pivot event types into boolean columns
    pivot_df = filtered_df.pivot_table(index=user_id_cols, columns=event_col, values="value", aggfunc="any", fill_value=False)
    pivot_df = pivot_df.reset_index()

    # Add metadata from first event per user
    metadata_df = filtered_df.drop_duplicates(subset=user_id_cols)[user_id_cols + extra_fields]

    # Merge all
    merged_df = (pivot_df.merge(metadata_df, on=user_id_cols, how="left").merge(count_df, on=user_id_cols, how="left"))

    # Save result
    merged_df.to_csv(filename, index=False)
    print(f"Transposed data saved to {filename} ({len(merged_df)} rows)")

if __name__ == "__main__":
    campaign_status_list = ['Email View', 'Email Click', 'Data Submission', 'Reported', 'No Action', 'TM Complete', 'TM Sent']
    your_region = "us"
    your_api_token = ""  

    campaigns = {"formatted_campaigngithub.csv": "2025 March - GitHub Notification (Targeted)","formatted_campaignzoom.csv": "2025 March - Zoom Missed Meeting", "formatted_campaignresume.csv": "2025 March - Download Resume"}

    for filename, campaign_name in campaigns.items():
        print(f"\nCollecting data for: {campaign_name}")
        filters = {"_campaignname": f"[\"{campaign_name}\"]"}
        data = get_phishing_data(your_region, your_api_token, filters=filters)
        save_transposed_csv(data, filename, campaign_status_list)
