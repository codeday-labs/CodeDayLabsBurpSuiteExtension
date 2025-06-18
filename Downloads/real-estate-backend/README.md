# 🏠 Real Estate Backend (Django + Supabase)

This is a backend API project for managing and querying real estate listings using:

- 🐍 Django & Django REST Framework
- 🐘 PostgreSQL (via Supabase)
- 🐳 Docker for development
- 📦 JSON API endpoint ready for integration

---

## 🚀 Features

- Connects to an existing **Supabase PostgreSQL** database
- Exposes listings as a clean **paginated JSON API**
- Django admin panel with full Supabase listing integration
- Easily extendable with filters, search, and authentication

---

## 📦 Prerequisites

Make sure you have the following installed:

- [Docker Desktop](https://www.docker.com/products/docker-desktop)
- [Git](https://git-scm.com/)

---

## 🛠️ Getting Started

### 1. Clone the Project

```bash
git clone https://github.com/<your-username>/real-estate-backend.git
cd real-estate-backend
```

2. Create a .env File
Create a .env file in the root directory with your Supabase connection info:

DB_NAME=postgres
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_HOST=your_supabase_host
DB_PORT=5432
✨ Tip: Use .env.example in the repo as a template

3. Start the App

### ▶️ Running Locally (with venv)

1. Create and activate a virtual environment:

```bash
python -m venv venv
source venv/bin/activate    # On Windows: venv\Scripts\activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the migrations to set up the database:

```bash
python manage.py migrate
```

4. Start the local server:

```bash
python manage.py runserver
```

5. Visit http://localhost:8000/api/listings/ to confirm the app connects successfully to the Supabase database.

### ▶️ Running in Docker
Build and start everything with Docker:

```bash
docker-compose up -d
```

Then open:

API Endpoint → http://localhost:8000/api/listings/

Admin Panel → http://localhost:8000/admin/

## 🏘️ Redfin to Supabase Sync

Download Redfin CSV listings manually and sync them into your Supabase database.

### 🔧 Setup

1. **Download the CSV file from Redfin**
2. **Clone the repo**
3. **Install Python dependencies (if not already installed)**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
4. **Fill in .env placeholders**:
   ```bash
   #redfin csv import
   CSV_FILE_PATH=<YOUR_PATH_HERE>
   #supabase credentials
   SUPABASE_KEY=<YOUR_SUPABASE_KEY_HERE>
   SUPABASE_URL=<YOUR_SUPABASE_URL_HERE>
   ```
   To get SUPABASE_KEY and SUPABASE URL:
   Project Overview>Project API
5. **Create table with proper columns in Supabase (If not create already)**:
   ```bash
   create table properties (
     "SALE TYPE" text,
     "SOLD DATE" text,
     "PROPERTY TYPE" text,
     "ADDRESS" text,
     "CITY" text,
     "STATE OR PROVINCE" text,
     "ZIP OR POSTAL CODE" text,
     "PRICE" numeric,
     "BEDS" numeric,
     "BATHS" numeric,
     "LOCATION" text,
     "SQUARE FEET" numeric,
     "LOT SIZE" numeric,
     "YEAR BUILT" numeric,
     "DAYS ON MARKET" numeric,
     "$/SQUARE FEET" numeric,
     "HOA/MONTH" numeric,
     "STATUS" text,
     "NEXT OPEN HOUSE START TIME" text,
     "NEXT OPEN HOUSE END TIME" text,
     "URL_INFO" text,
     "SOURCE" text,
     "MLS#" text primary key,
     "FAVORITE" text,
     "INTERESTED" text,
     "LATITUDE" numeric,
     "LONGITUDE" numeric
   );
   ```
6. **Run the script**:
   python listings/redfin_to_supabase.py