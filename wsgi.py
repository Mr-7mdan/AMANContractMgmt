import os
from app import app
from config import Config

# Load production configuration
app.config.from_object(Config)

if __name__ == "__main__":
    app.run() 