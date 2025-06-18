import os
import pandas as pd
from supabase import create_client, Client
from dotenv import load_dotenv
import numpy as np # Import numpy for np.nan check

# Load environment variables from .env file
load_dotenv()

# Supabase credentials
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("Supabase URL or Key not found in .env file.")

# Initialize Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Define the path to your CSV file
csv_file_path = os.path.expanduser(os.getenv("CSV_FILE_PATH"))

# Define your Supabase table name
supabase_table_name = "properties"  # Changed to 'properties' based on your output

def import_csv_to_supabase(csv_path: str, table_name: str):
    try:
        df = pd.read_csv(csv_path)

        original_column_name = "URL (SEE https://www.redfin.com/buy-a-home/comparative-market-analysis FOR INFO ON PRICING)"
        if original_column_name in df.columns:
            df.rename(columns={original_column_name: "URL_INFO"}, inplace=True)
            print(f"Column '{original_column_name}' renamed to 'URL_INFO'.")
        else:
            print(f"Warning: Column '{original_column_name}' not found in CSV. No renaming performed for this column.")

        # --- FIX FOR PRIMARY KEY: Drop rows where 'MLS#' is NaN ---
        if 'MLS#' in df.columns:
            initial_rows = len(df)
            df.dropna(subset=['MLS#'], inplace=True)
            rows_dropped = initial_rows - len(df)
            if rows_dropped > 0:
                print(f"Dropped {rows_dropped} rows due to missing 'MLS#' primary key values.")
        else:
            print("Warning: 'MLS#' column not found in CSV. No rows dropped based on MLS#.")



        # --- IMPORTANT FIX: Handle NaN values ---
        # Convert all NaN values in the DataFrame to None, which Supabase will interpret as NULL
        # This is generally the safest approach for numerical columns that might have missing data.
        df = df.replace({np.nan: None})
        # If you only want to apply this to specific columns (e.g., all numeric ones):
        # for col in df.select_dtypes(include=[np.number]).columns:
        #     df[col] = df[col].replace({np.nan: None})
        # For non-numeric columns, np.nan might not apply as directly for empty strings,
        # but df.replace({np.nan: None}) will generally handle it correctly for all types.

        # Convert DataFrame to a list of dictionaries for Supabase insertion
        records = df.to_dict(orient="records")

        # Insert data into Supabase
        response = supabase.table(table_name).insert(records).execute()

        # Check for both data and error parts of the response
        if response.data:
            print(f"Successfully imported {len(response.data)} records into '{table_name}'.")
        elif response.error:
            print(f"Error importing data: {response.error}")
        else:
            print("No data imported and no error reported. Check Supabase RLS policies or table definition.")


    except FileNotFoundError:
        print(f"Error: CSV file not found at '{csv_path}'. Please check the path.")
    except pd.errors.EmptyDataError:
        print("Error: The CSV file is empty.")
    except pd.errors.ParserError:
        print("Error: Could not parse the CSV file. Check its format.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    print(f"Attempting to import '{csv_file_path}' into Supabase table '{supabase_table_name}'...")
    import_csv_to_supabase(csv_file_path, supabase_table_name)