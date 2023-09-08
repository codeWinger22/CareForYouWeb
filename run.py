import os
from waitress import serve
from app import app  # Import your app

# Run from the same directory as this script
this_files_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(this_files_dir)

# Run the app on 0.0.0.0 (allow connections from any IP) and the desired port
serve(app, host='0.0.0.0')
