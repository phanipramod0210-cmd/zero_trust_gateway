-- Zero-Trust AI Gateway — PostgreSQL initialization
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
GRANT ALL PRIVILEGES ON DATABASE zt_db TO zt_user;
