import psycopg2

def get_connection():
     """Create and return a new database connection."""
     return psycopg2.connect(
         database="workdesk_db",
         user="postgres",
         password="00478965",
         host="localhost",
         port="5432"
     )