import os
import zipfile
import shutil
import logging
from pathlib import Path
import sys
from datetime import datetime

class MalwareUnpacker:
    def __init__(self, source_dir, extract_dir, zip_password="infected"):
        self.source_dir = Path(source_dir)
        self.extract_dir = Path(extract_dir)
        self.zip_password = zip_password.encode()
        self.setup_logging()
        
    def setup_logging(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = f"unpacking_log_{timestamp}.txt"
        
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )

    def unzip_file(self, zip_path, extract_path, password=True):
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                if password:
                    logging.debug(f"Contents of ZIP file {zip_path}: {zip_ref.namelist()}")
                    zip_ref.extractall(path=extract_path, pwd=self.zip_password)
                else:
                    zip_ref.extractall(path=extract_path)
            return True
        except Exception as e:
            logging.error(f"Error extracting {zip_path}: {str(e)}")
            return False

    def process_apt_archive(self, apt_zip):
        try:
            logging.info(f"\nProcessing APT archive: {apt_zip}")
            
            # Create APT directory
            apt_name = apt_zip.stem
            apt_dir = self.extract_dir / apt_name
            apt_dir.mkdir(parents=True, exist_ok=True)
            logging.debug(f"Created APT directory: {apt_dir}")

            # Create exe and others directories
            exe_dir = apt_dir / "exe"
            others_dir = apt_dir / "others"
            exe_dir.mkdir(exist_ok=True)
            others_dir.mkdir(exist_ok=True)
            logging.debug(f"Created exe directory: {exe_dir}")
            logging.debug(f"Created others directory: {others_dir}")

            # First, extract the main APT archive to a temporary location
            temp_dir = apt_dir / "temp"
            temp_dir.mkdir(exist_ok=True)
            
            if not self.unzip_file(apt_zip, temp_dir, password=True):
                logging.error(f"Failed to extract main APT archive: {apt_zip}")
                return

            # Look for and process the inner APT folder
            inner_folders = list(temp_dir.glob("*"))
            for folder in inner_folders:
                if folder.is_dir():
                    logging.debug(f"Processing inner folder: {folder}")
                    
                    # Process exe folder
                    exe_source = folder / "exe"
                    if exe_source.exists():
                        logging.debug(f"Found exe folder: {exe_source}")
                        for zip_file in exe_source.glob("*.zip"):
                            logging.info(f"Extracting exe file: {zip_file}")
                            if self.unzip_file(zip_file, exe_dir, password=True):
                                logging.debug(f"Successfully extracted: {zip_file}")
                            else:
                                logging.error(f"Failed to extract: {zip_file}")

                    # Process others folder
                    others_source = folder / "others"
                    if others_source.exists():
                        logging.debug(f"Found others folder: {others_source}")
                        for zip_file in others_source.glob("*.zip"):
                            logging.info(f"Extracting others file: {zip_file}")
                            if self.unzip_file(zip_file, others_dir, password=True):
                                logging.debug(f"Successfully extracted: {zip_file}")
                            else:
                                logging.error(f"Failed to extract: {zip_file}")

            # Cleanup temporary directory
            shutil.rmtree(temp_dir)
            logging.debug(f"Cleaned up temporary directory: {temp_dir}")

        except Exception as e:
            logging.error(f"Error processing APT archive {apt_zip}: {str(e)}")
            raise

    def unpack_all(self):
        logging.info(f"Starting unpacking process at {datetime.now()}")
        logging.info(f"Source directory: {self.source_dir}")
        logging.info(f"Extract directory: {self.extract_dir}")
        
        if not self.source_dir.exists():
            raise Exception(f"Source directory does not exist: {self.source_dir}")
        
        self.extract_dir.mkdir(parents=True, exist_ok=True)
        
        # List all zip files in source directory
        zip_files = list(self.source_dir.glob("*.zip"))
        logging.info(f"Found {len(zip_files)} zip files to process")
        
        if not zip_files:
            logging.warning(f"No zip files found in {self.source_dir}")
            return
        
        for apt_zip in zip_files:
            try:
                self.process_apt_archive(apt_zip)
            except Exception as e:
                logging.error(f"Failed to process {apt_zip}: {str(e)}")
                continue
            
        logging.info(f"\nUnpacking process completed at {datetime.now()}")

def main():
    # Updated paths
    source_dir = r"C:/Users/MCTI Student/Desktop/Sub 3/Submission-2"
    extract_dir = r"C:/Users/MCTI Student/Desktop/Sub 3/Unpacked_Samples"
    
    print(f"Starting unpacking process...")
    print(f"Source directory: {source_dir}")
    print(f"Extract directory: {extract_dir}")
    
    try:
        unpacker = MalwareUnpacker(source_dir, extract_dir)
        unpacker.unpack_all()
        print("Unpacking completed successfully!")
    except Exception as e:
        print(f"\nError: {str(e)}")
        print("Please check if the directories exist and you have proper permissions.")
        sys.exit(1)

if __name__ == "__main__":
    main()