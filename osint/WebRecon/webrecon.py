#!/usr/bin/env python3
"""
WebRecon Pro - Advanced OSINT Web Reconnaissance Tool
Enhanced with Image Downloading Capabilities
Author: D4rk_Intel
Project: OSINT Reconnaissance Tool
"""

import os
import re
import json
import argparse
import requests
import time
import urllib.parse
import tldextract
import socket
import threading
from datetime import datetime
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Suppress ALL warnings
import warnings
warnings.filterwarnings("ignore")

class ColorOutput:
    @staticmethod
    def info(msg):
        print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def success(msg):
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def warning(msg):
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def error(msg):
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def finding(msg):
        print(f"{Fore.MAGENTA}[FINDING]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def whois(msg):
        print(f"{Fore.BLUE}[WHOIS]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def dns(msg):
        print(f"{Fore.CYAN}[DNS]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def image(msg):
        print(f"{Fore.LIGHTMAGENTA_EX}[IMAGE]{Style.RESET_ALL} {msg}")

class URLUtils:
    @staticmethod
    def is_valid_url(url):
        """Validate URL format and structure"""
        try:
            result = urllib.parse.urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    @staticmethod
    def get_domain(url):
        """Extract domain from URL"""
        extracted = tldextract.extract(url)
        return f"{extracted.domain}.{extracted.suffix}"
    
    @staticmethod
    def get_subdomain(url):
        """Extract subdomain from URL"""
        extracted = tldextract.extract(url)
        return extracted.subdomain
    
    @staticmethod
    def normalize_url(url):
        """Normalize URL for consistent comparison"""
        parsed = urllib.parse.urlparse(url)
        normalized = urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc.lower(),
            parsed.path,
            '',  # params
            '',  # query
            ''   # fragment
        ))
        return normalized.rstrip('/')
    
    @staticmethod
    def should_skip_url(url):
        """Check if URL should be skipped (email protection, etc.)"""
        skip_patterns = [
            r'cdn-cgi/l/email-protection',  # Cloudflare email protection
            r'mailto:',  # Mailto links
            r'tel:',  # Telephone links
            r'javascript:',  # JavaScript links
            r'#',  # Anchor links
            r'hubspot\.com',  # HubSpot URLs that cause DNS issues
            r'linkedin\.com/psettings',  # LinkedIn settings
            r'facebook\.com/sharer',  # Facebook share links
            r'twitter\.com/intent',  # Twitter intent links
            r'facebook\.com/.*[0-9]{15,}',  # Facebook numeric IDs
        ]
        
        url_lower = url.lower()
        return any(re.search(pattern, url_lower) for pattern in skip_patterns)

class Config:
    def __init__(self):
        # Request Configuration
        self.USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        self.TIMEOUT = 30
        self.MAX_RETRIES = 3
        
        # Crawler Configuration
        self.MAX_PAGES = 100
        self.MAX_DEPTH = 2
        self.CRAWL_DELAY = 1
        
        # Output Configuration
        self.OUTPUT_DIR = "webrecon_output"
        self.IMAGE_DIR = "images"
        
        # Proxy Configuration
        self.HTTP_PROXY = os.getenv('HTTP_PROXY')
        self.SOCKS_PROXY = os.getenv('SOCKS_PROXY')
        
        # Image Download Configuration
        self.DOWNLOAD_IMAGES = True
        self.MAX_IMAGES_PER_PAGE = 20
        self.MIN_IMAGE_SIZE = 1024  # Minimum size in bytes (1KB)
        self.MAX_IMAGE_SIZE = 10485760  # Maximum size in bytes (10MB)
        self.IMAGE_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg', '.ico']
        self.CREATE_THUMBNAILS = True
        self.THUMBNAIL_SIZE = (200, 200)  # Width x Height for thumbnails

class PatternMatcher:
    # Email patterns
    EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    
    # Cloud storage patterns
    AWS_S3_PATTERN = r'https?://[a-zA-Z0-9.-]*\.?s3[.-]([a-z0-9-]+)?\.amazonaws\.com'
    AZURE_BLOB_PATTERN = r'https?://[a-zA-Z0-9.-]*\.blob\.core\.windows\.net'
    GCP_STORAGE_PATTERN = r'https?://storage\.cloud\.google\.com/[^\s"\']+'
    
    # Social media patterns
    SOCIAL_MEDIA_PATTERNS = {
        'facebook': r'https?://(?:www\.)?facebook\.com/[^\s"\']+',
        'twitter': r'https?://(?:www\.)?twitter\.com/[^\s"\']+',
        'linkedin': r'https?://(?:www\.)?linkedin\.com/(?:company/[^\s"\']+|in/[^\s"\']+|showcase/[^\s"\']+)',
        'instagram': r'https?://(?:www\.)?instagram\.com/[^\s"\']+',
        'youtube': r'https?://(?:www\.)?youtube\.com/[^\s"\']+',
        'github': r'https?://(?:www\.)?github\.com/[^\s"\']+'
    }
    
    # File patterns
    FILE_PATTERNS = {
        'pdf': r'[^"\']+\.pdf(?:\?[^"\']*)?',
        'doc': r'[^"\']+\.(?:doc|docx)(?:\?[^"\']*)?',
        'xls': r'[^"\']+\.(?:xls|xlsx)(?:\?[^"\']*)?',
        'ppt': r'[^"\']+\.(?:ppt|pptx)(?:\?[^"\']*)?',
        'txt': r'[^"\']+\.txt(?:\?[^"\']*)?',
        'csv': r'[^"\']+\.csv(?:\?[^"\']*)?',
        'zip': r'[^"\']+\.(?:zip|rar|7z)(?:\?[^"\']*)?',
        'config': r'[^"\']+\.(?:config|conf|ini)(?:\?[^"\']*)?',
        'sql': r'[^"\']+\.sql(?:\?[^"\']*)?',
        'log': r'[^"\']+\.log(?:\?[^"\']*)?'
    }
    
    # Image patterns
    IMAGE_PATTERNS = {
        'jpg': r'[^"\']+\.(?:jpg|jpeg)(?:\?[^"\']*)?',
        'png': r'[^"\']+\.png(?:\?[^"\']*)?',
        'gif': r'[^"\']+\.gif(?:\?[^"\']*)?',
        'webp': r'[^"\']+\.webp(?:\?[^"\']*)?',
        'svg': r'[^"\']+\.svg(?:\?[^"\']*)?',
        'ico': r'[^"\']+\.ico(?:\?[^"\']*)?',
        'bmp': r'[^"\']+\.bmp(?:\?[^"\']*)?',
        'tiff': r'[^"\']+\.(?:tiff|tif)(?:\?[^"\']*)?'
    }

class ImageDownloader:
    def __init__(self, config, base_url, output_dir=None):
        self.config = config
        self.base_url = base_url
        self.base_domain = URLUtils.get_domain(base_url)
        
        # Set up image directories
        if output_dir:
            self.output_dir = output_dir
        else:
            self.output_dir = os.path.join(config.OUTPUT_DIR, config.IMAGE_DIR, self.base_domain)
        
        # Create image directories
        self.raw_image_dir = os.path.join(self.output_dir, "raw")
        self.thumbnails_dir = os.path.join(self.output_dir, "thumbnails")
        self.extracted_dir = os.path.join(self.output_dir, "extracted")
        
        for directory in [self.output_dir, self.raw_image_dir, self.thumbnails_dir, self.extracted_dir]:
            os.makedirs(directory, exist_ok=True)
        
        # Session for downloading
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': config.USER_AGENT})
        
        # Track downloaded images
        self.downloaded_images = []
        self.failed_downloads = []
        self.total_downloaded_size = 0
        
        # Create metadata file
        self.metadata_file = os.path.join(self.output_dir, "metadata.json")
        self.metadata = {
            'total_downloaded': 0,
            'total_size': 0,
            'images': [],
            'timestamp': datetime.now().isoformat()
        }
    
    def extract_image_urls(self, soup, page_url):
        """Extract all image URLs from a BeautifulSoup object"""
        image_urls = []
        
        # Extract from img tags
        for img_tag in soup.find_all('img'):
            src = img_tag.get('src') or img_tag.get('data-src') or img_tag.get('data-lazy-src')
            if src:
                # Skip placeholder images and icons
                if self._should_skip_image(src):
                    continue
                    
                # Convert relative URLs to absolute
                full_url = urllib.parse.urljoin(page_url, src)
                
                # Validate URL and check extension
                if URLUtils.is_valid_url(full_url) and self._is_image_url(full_url):
                    image_urls.append(full_url)
        
        # Extract from CSS backgrounds
        for element in soup.find_all(style=True):
            style = element['style']
            # Look for url() patterns in CSS
            bg_images = re.findall(r'url\(["\']?(.*?)["\']?\)', style, re.IGNORECASE)
            for bg_url in bg_images:
                if self._is_image_url(bg_url):
                    full_url = urllib.parse.urljoin(page_url, bg_url)
                    if URLUtils.is_valid_url(full_url):
                        image_urls.append(full_url)
        
        # Extract from meta tags (favicons, og:image, etc.)
        meta_images = []
        for meta_tag in soup.find_all('meta'):
            property_name = meta_tag.get('property', '').lower()
            content = meta_tag.get('content', '')
            
            if property_name in ['og:image', 'twitter:image', 'image'] and content:
                full_url = urllib.parse.urljoin(page_url, content)
                if URLUtils.is_valid_url(full_url) and self._is_image_url(full_url):
                    meta_images.append(full_url)
        
        # Combine and deduplicate
        all_images = list(set(image_urls + meta_images))
        
        # Limit number of images per page
        if len(all_images) > self.config.MAX_IMAGES_PER_PAGE:
            ColorOutput.info(f"Limiting images from {len(all_images)} to {self.config.MAX_IMAGES_PER_PAGE} per page")
            all_images = all_images[:self.config.MAX_IMAGES_PER_PAGE]
        
        return all_images
    
    def _should_skip_image(self, image_url):
        """Check if image should be skipped (placeholders, icons, etc.)"""
        skip_patterns = [
            r'blank\.(?:png|jpg|gif)',
            r'placeholder\.(?:png|jpg|gif)',
            r'spacer\.(?:png|jpg|gif)',
            r'pixel\.(?:png|jpg|gif)',
            r'1x1\.(?:png|jpg|gif)',
            r'^data:image/',  # Skip data URIs
            r'^javascript:',  # Skip JS
            r'loading\.(?:png|jpg|gif)',
            r'icon-',  # Icons
            r'favicon',
            r'\.ico$',
            r'\.svg$',  # Skip SVGs initially
        ]
        
        image_url_lower = image_url.lower()
        return any(re.search(pattern, image_url_lower) for pattern in skip_patterns)
    
    def _is_image_url(self, url):
        """Check if URL points to an image file"""
        url_lower = url.lower()
        
        # Check file extensions
        for ext in self.config.IMAGE_EXTENSIONS:
            if url_lower.endswith(ext) or ext in url_lower:
                return True
        
        # Check for image patterns in query string
        image_patterns = [
            r'\.(?:jpg|jpeg|png|gif|bmp|webp|svg|ico)',
            r'format=(?:jpg|jpeg|png|gif|bmp|webp)',
            r'type=(?:image|img)',
            r'image/'
        ]
        
        return any(re.search(pattern, url_lower) for pattern in image_patterns)
    
    def download_image(self, image_url, page_url):
        """Download a single image"""
        try:
            # Get filename from URL
            parsed_url = urllib.parse.urlparse(image_url)
            filename = os.path.basename(parsed_url.path)
            
            # If no extension or weird filename, generate one
            if not filename or '.' not in filename or len(filename) > 100:
                # Generate filename from URL hash
                import hashlib
                url_hash = hashlib.md5(image_url.encode()).hexdigest()[:8]
                filename = f"image_{url_hash}.jpg"
            else:
                # Clean filename
                filename = re.sub(r'[^\w\-\.]', '_', filename)
            
            # Create safe filename
            safe_filename = filename[:100]  # Limit filename length
            
            # Check if already downloaded
            raw_filepath = os.path.join(self.raw_image_dir, safe_filename)
            if os.path.exists(raw_filepath):
                ColorOutput.info(f"Image already downloaded: {safe_filename}")  # CHANGED: WARNING -> INFO
                return None
            
            # Download image
            response = self.session.get(image_url, timeout=self.config.TIMEOUT, stream=True)
            
            if response.status_code == 200:
                # Check content type
                content_type = response.headers.get('content-type', '')
                if not content_type.startswith('image/'):
                    ColorOutput.info(f"Skipping non-image content: {content_type}")  # CHANGED: WARNING -> INFO
                    return None
                
                # Check file size
                content_length = response.headers.get('content-length')
                if content_length:
                    file_size = int(content_length)
                    if file_size < self.config.MIN_IMAGE_SIZE:
                        ColorOutput.info(f"Skipping small image ({file_size} bytes)")  # CHANGED: WARNING -> INFO
                        return None
                    if file_size > self.config.MAX_IMAGE_SIZE:
                        ColorOutput.info(f"Skipping large image ({file_size} bytes)")  # CHANGED: WARNING -> INFO
                        return None
                
                # Save image
                with open(raw_filepath, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                
                # Get actual file size
                file_size = os.path.getsize(raw_filepath)
                
                # Create thumbnail if enabled
                thumbnail_path = None
                if self.config.CREATE_THUMBNAILS and file_size > 0:
                    thumbnail_path = self._create_thumbnail(raw_filepath, safe_filename)
                
                # Extract metadata
                metadata = self._extract_image_metadata(raw_filepath, image_url, page_url)
                
                # Update statistics
                self.total_downloaded_size += file_size
                
                # Add to metadata
                image_info = {
                    'filename': safe_filename,
                    'original_url': image_url,
                    'source_page': page_url,
                    'file_size': file_size,
                    'download_time': datetime.now().isoformat(),
                    'thumbnail': thumbnail_path,
                    'metadata': metadata
                }
                
                self.downloaded_images.append(image_info)
                
                ColorOutput.image(f"Downloaded: {safe_filename} ({self._format_file_size(file_size)}) from {page_url}")
                
                return image_info
                
            else:
                ColorOutput.info(f"Failed to download (HTTP {response.status_code}): {image_url}")  # CHANGED: WARNING -> INFO
                self.failed_downloads.append(image_url)
                return None
                
        except Exception as e:
            ColorOutput.info(f"Error downloading {image_url}: {str(e)[:100]}")  # CHANGED: ERROR -> INFO
            self.failed_downloads.append(image_url)
            return None
    
    def _create_thumbnail(self, image_path, original_filename):
        """Create thumbnail for image"""
        try:
            from PIL import Image
            
            # Generate thumbnail filename
            name, ext = os.path.splitext(original_filename)
            thumbnail_filename = f"{name}_thumb{ext}"
            thumbnail_path = os.path.join(self.thumbnails_dir, thumbnail_filename)
            
            # Skip if thumbnail already exists
            if os.path.exists(thumbnail_path):
                return thumbnail_filename
            
            # Open and create thumbnail
            with Image.open(image_path) as img:
                # Convert to RGB if necessary
                if img.mode in ('RGBA', 'LA', 'P'):
                    img = img.convert('RGB')
                
                # Create thumbnail
                img.thumbnail(self.config.THUMBNAIL_SIZE)
                
                # Save thumbnail
                img.save(thumbnail_path, quality=85)
                
                return thumbnail_filename
                
        except ImportError:
            ColorOutput.info("PIL/Pillow not installed. Thumbnails disabled.")
            return None
        except Exception as e:
            ColorOutput.info(f"Could not create thumbnail: {str(e)[:100]}")
            return None
    
    def _extract_image_metadata(self, image_path, image_url, page_url):
        """Extract metadata from image file"""
        metadata = {
            'url': image_url,
            'source_page': page_url,
            'filename': os.path.basename(image_path),
            'file_size': os.path.getsize(image_path),
            'file_type': os.path.splitext(image_path)[1].lower(),
            'download_time': datetime.now().isoformat()
        }
        
        try:
            from PIL import Image
            import PIL.ExifTags
            
            with Image.open(image_path) as img:
                # Basic image info
                metadata['dimensions'] = {
                    'width': img.width,
                    'height': img.height,
                    'mode': img.mode
                }
                
                # EXIF data
                exif_data = {}
                if hasattr(img, '_getexif') and img._getexif():
                    for tag, value in img._getexif().items():
                        if tag in PIL.ExifTags.TAGS:
                            tag_name = PIL.ExifTags.TAGS[tag]
                            # Convert to string for JSON serialization
                            try:
                                exif_data[tag_name] = str(value)
                            except:
                                exif_data[tag_name] = "Non-serializable data"
                
                if exif_data:
                    metadata['exif'] = exif_data
                    
        except Exception:
            pass  # Silent fail for metadata extraction
        
        return metadata
    
    def _format_file_size(self, size_bytes):
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    def download_images_from_page(self, soup, page_url):
        """Download all images from a page"""
        if not self.config.DOWNLOAD_IMAGES:
            return []
        
        ColorOutput.info(f"Extracting images from: {page_url}")
        
        # Extract image URLs
        image_urls = self.extract_image_urls(soup, page_url)
        
        if not image_urls:
            ColorOutput.info(f"No images found on page: {page_url}")
            return []
        
        ColorOutput.info(f"Found {len(image_urls)} potential images on page")
        
        downloaded_images = []
        for image_url in image_urls:
            image_info = self.download_image(image_url, page_url)
            if image_info:
                downloaded_images.append(image_info)
            
            # Small delay to avoid overwhelming the server
            time.sleep(0.1)
        
        return downloaded_images
    
    def save_metadata(self):
        """Save metadata about downloaded images"""
        self.metadata['total_downloaded'] = len(self.downloaded_images)
        self.metadata['total_size'] = self.total_downloaded_size
        self.metadata['failed_downloads'] = len(self.failed_downloads)
        self.metadata['images'] = self.downloaded_images
        
        try:
            with open(self.metadata_file, 'w', encoding='utf-8') as f:
                json.dump(self.metadata, f, indent=2, ensure_ascii=False)
            
            # Also save a CSV summary
            csv_file = os.path.join(self.output_dir, "images_summary.csv")
            self._save_csv_summary(csv_file)
            
            ColorOutput.success(f"Image metadata saved to: {self.metadata_file}")
            
        except Exception as e:
            ColorOutput.info(f"Could not save metadata: {str(e)[:100]}")
    
    def _save_csv_summary(self, csv_file):
        """Save summary as CSV file"""
        try:
            import csv
            
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow([
                    'Filename', 'Original URL', 'Source Page', 
                    'File Size (bytes)', 'Width', 'Height', 
                    'File Type', 'Download Time'
                ])
                
                # Write data
                for img in self.downloaded_images:
                    writer.writerow([
                        img['filename'],
                        img['original_url'],
                        img['source_page'],
                        img.get('file_size', 0),
                        img.get('metadata', {}).get('dimensions', {}).get('width', 'N/A'),
                        img.get('metadata', {}).get('dimensions', {}).get('height', 'N/A'),
                        img.get('metadata', {}).get('file_type', 'N/A'),
                        img.get('download_time', 'N/A')
                    ])
                    
            ColorOutput.info(f"CSV summary saved to: {csv_file}")
            
        except ImportError:
            ColorOutput.info("CSV module not available, skipping CSV export")
        except Exception as e:
            ColorOutput.info(f"Could not save CSV summary: {str(e)[:100]}")
    
    def generate_html_gallery(self):
        """Generate HTML gallery of downloaded images"""
        try:
            html_file = os.path.join(self.output_dir, "gallery.html")
            
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Image Gallery - WebRecon Pro</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background-color: #333;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .gallery {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 20px;
        }}
        .image-card {{
            background-color: white;
            border-radius: 5px;
            padding: 15px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }}
        .image-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }}
        .thumbnail {{
            width: 100%;
            height: 200px;
            object-fit: cover;
            border-radius: 3px;
            margin-bottom: 10px;
        }}
        .image-info {{
            font-size: 12px;
            color: #666;
        }}
        .image-info strong {{
            color: #333;
        }}
        .stats {{
            background-color: white;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .download-link {{
            display: inline-block;
            margin-top: 10px;
            padding: 8px 15px;
            background-color: #4CAF50;
            color: white;
            text-decoration: none;
            border-radius: 3px;
        }}
        .download-link:hover {{
            background-color: #45a049;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>WebRecon Pro - Image Gallery</h1>
        <p>Domain: {self.base_domain} | Total Images: {len(self.downloaded_images)}</p>
        <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>
    
    <div class="stats">
        <h2>Download Statistics</h2>
        <p><strong>Total Images:</strong> {len(self.downloaded_images)}</p>
        <p><strong>Total Size:</strong> {self._format_file_size(self.total_downloaded_size)}</p>
        <p><strong>Failed Downloads:</strong> {len(self.failed_downloads)}</p>
        <a href="images_summary.csv" class="download-link">Download CSV Summary</a>
        <a href="metadata.json" class="download-link">Download Metadata JSON</a>
    </div>
    
    <div class="gallery">
""")
                
                # Add image cards
                for img in self.downloaded_images:
                    thumbnail_path = img.get('thumbnail')
                    if thumbnail_path and os.path.exists(os.path.join(self.thumbnails_dir, thumbnail_path)):
                        thumb_src = f"thumbnails/{thumbnail_path}"
                    else:
                        thumb_src = f"raw/{img['filename']}"
                    
                    f.write(f"""
        <div class="image-card">
            <img src="{thumb_src}" alt="{img['filename']}" class="thumbnail">
            <div class="image-info">
                <p><strong>File:</strong> {img['filename']}</p>
                <p><strong>Size:</strong> {self._format_file_size(img.get('file_size', 0))}</p>
                <p><strong>Source:</strong> {os.path.basename(img['source_page'])}</p>
                <p><a href="raw/{img['filename']}" target="_blank">View Original</a></p>
            </div>
        </div>
""")
                
                f.write("""
    </div>
    
    <script>
        // Simple image lightbox functionality
        document.addEventListener('DOMContentLoaded', function() {
            const thumbnails = document.querySelectorAll('.thumbnail');
            thumbnails.forEach(thumb => {
                thumb.addEventListener('click', function() {
                    const originalSrc = this.closest('.image-card').querySelector('a').href;
                    window.open(originalSrc, '_blank');
                });
                thumb.style.cursor = 'pointer';
            });
        });
    </script>
</body>
</html>""")
            
            ColorOutput.success(f"HTML gallery generated: {html_file}")
            
        except Exception as e:
            ColorOutput.info(f"Could not generate HTML gallery: {str(e)[:100]}")
    
    def print_summary(self):
        """Print image download summary"""
        if self.downloaded_images:
            ColorOutput.info("\n" + "="*60)
            ColorOutput.info("IMAGE DOWNLOAD SUMMARY")
            ColorOutput.info("="*60)
            ColorOutput.success(f"Total images downloaded: {len(self.downloaded_images)}")
            ColorOutput.success(f"Total size: {self._format_file_size(self.total_downloaded_size)}")
            ColorOutput.success(f"Images saved to: {self.output_dir}")
            
            if self.failed_downloads:
                ColorOutput.info(f"Failed to download: {len(self.failed_downloads)} images")
            
            # Show some sample downloaded images
            ColorOutput.info("\nSample downloaded images:")
            for img in self.downloaded_images[:5]:
                ColorOutput.image(f"  {img['filename']} ({self._format_file_size(img.get('file_size', 0))})")
            
            if len(self.downloaded_images) > 5:
                ColorOutput.info(f"  ... and {len(self.downloaded_images) - 5} more")
        else:
            ColorOutput.info("No images were downloaded during this session")

# DataExtractor class (truncated for brevity, but all methods remain the same)
class DataExtractor:
    def __init__(self, base_url):
        self.base_url = base_url
        self.base_domain = URLUtils.get_domain(base_url)
        self.pattern_matcher = PatternMatcher()
    
    def extract_emails(self, text):
        """Extract email addresses from text with filtering"""
        emails = set(re.findall(self.pattern_matcher.EMAIL_PATTERN, text, re.IGNORECASE))
        
        # Filter out false positives
        filtered_emails = []
        for email in emails:
            email_lower = email.lower()
            
            # Skip common placeholder emails and false positives
            false_positive_domains = [
                'example.com', 'domain.com', 'email.com', 'test.com',
                'yourdomain.com', 'sentry.io', 'wixpress.com', 'sentry-next.wixpress.com',
                'localhost', '127.0.0.1', 'your-email.com', 'company.com',
                'placeholder.com', 'fake.com', 'test.org', 'example.org'
            ]
            
            false_positive_patterns = [
                r'noreply@', r'no-reply@', r'support@.*\.test', r'info@.*\.local',
                r'admin@.*\.local', r'root@', r'postmaster@', r'webmaster@',
                r'^[a-f0-9]{32}@',  # Filter hex hash emails
                r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}@',  # UUID emails
            ]
            
            should_filter = (
                any(domain in email_lower for domain in false_positive_domains) or
                any(re.search(pattern, email_lower) for pattern in false_positive_patterns) or
                len(email) < 6 or  # Too short
                '..' in email or  # Double dots
                email.count('@') != 1 or  # Multiple @ symbols
                email.startswith('.') or email.endswith('.')  # Starts or ends with dot
            )
            
            if not should_filter and self._is_likely_real_email(email):
                filtered_emails.append(email)
        
        unique_emails = list(set(filtered_emails))
        for email in unique_emails:
            ColorOutput.finding(f"Email found: {email}")
        
        return unique_emails
    
    def _is_likely_real_email(self, email):
        """Check if email appears to be from a real person/organization"""
        email_lower = email.lower()
        
        real_patterns = [
            r'^[a-zA-Z]+\.[a-zA-Z]+@',
            r'^[a-zA-Z]+@',
            r'^[a-zA-Z][a-zA-Z0-9._-]*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        ]
        
        system_patterns = [
            r'^[a-f0-9]+@',
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}@',
            r'^[0-9]+@',
            r'^[a-z0-9]{32}@',
            r'@sentry\.',
            r'@.*\.sentry\.',
            r'@.*\.local$',
            r'@.*\.test$',
        ]
        
        if not any(re.search(pattern, email_lower) for pattern in real_patterns):
            return False
        
        if any(re.search(pattern, email_lower) for pattern in system_patterns):
            return False
        
        return True
    
    def extract_social_media(self, text):
        """Extract social media URLs from text"""
        social_media = {}
        
        improved_patterns = {
            'facebook': [
                r'https?://(?:www\.)?facebook\.com/(?!sharer\.php)(?![^/]*\/sharer\.php)(?![^/]*\/share\.php)([a-zA-Z0-9\.\-]+)',
                r'https?://(?:www\.)?fb\.com/([a-zA-Z0-9\.\-]+)'
            ],
            'twitter': [
                r'https?://(?:www\.)?twitter\.com/(?!share|intent/tweet)([a-zA-Z0-9_]+)',
                r'https?://(?:www\.)?x\.com/([a-zA-Z0-9_]+)'
            ],
            'linkedin': [
                r'https?://(?:www\.)?linkedin\.com/company/([a-zA-Z0-9\-]+)/?',
                r'https?://(?:www\.)?linkedin\.com/in/([a-zA-Z0-9\-]+)/?',
                r'https?://(?:www\.)?linkedin\.com/showcase/([a-zA-Z0-9\-]+)/?',
                r'https?://(?:www\.)?linkedin\.com/school/([a-zA-Z0-9\-]+)/?',
                r'https?://(?:www\.)?linkedin\.com/pages/([a-zA-Z0-9\-]+)/?'
            ],
            'instagram': [
                r'https?://(?:www\.)?instagram\.com/([a-zA-Z0-9\._]+)'
            ],
            'youtube': [
                r'https?://(?:www\.)?youtube\.com/(?!redirect|embed)(?:c/|channel/|user/|@)?([a-zA-Z0-9\-_]+)',
                r'https?://(?:www\.)?youtu\.be/([a-zA-Z0-9\-_]+)'
            ],
            'github': [
                r'https?://(?:www\.)?github\.com/([a-zA-Z0-9\-_]+)'
            ]
        }
        
        for platform, patterns in improved_patterns.items():
            matches = set()
            for pattern in patterns:
                found = re.findall(pattern, text, re.IGNORECASE)
                for match in found:
                    if platform == 'facebook':
                        clean_url = f"https://www.facebook.com/{match}"
                    elif platform == 'twitter':
                        clean_url = f"https://www.twitter.com/{match}"
                    elif platform == 'linkedin':
                        if 'company' in pattern:
                            clean_url = f"https://www.linkedin.com/company/{match}"
                        elif 'in' in pattern:
                            clean_url = f"https://www.linkedin.com/in/{match}"
                        elif 'showcase' in pattern:
                            clean_url = f"https://www.linkedin.com/showcase/{match}"
                        elif 'school' in pattern:
                            clean_url = f"https://www.linkedin.com/school/{match}"
                        elif 'pages' in pattern:
                            clean_url = f"https://www.linkedin.com/pages/{match}"
                        else:
                            clean_url = f"https://www.linkedin.com/company/{match}"
                    elif platform == 'instagram':
                        clean_url = f"https://www.instagram.com/{match}"
                    elif platform == 'youtube':
                        clean_url = f"https://www.youtube.com/{match}"
                    elif platform == 'github':
                        clean_url = f"https://www.github.com/{match}"
                    
                    if self._is_valid_social_url(clean_url):
                        matches.add(clean_url)
            
            if matches:
                social_media[platform] = list(matches)
        
        return social_media
    
    def _is_valid_social_url(self, url):
        """Filter out social media false positives"""
        false_positive_indicators = [
            'sharer.php', 'share.php', 'share', 'intent/tweet', 
            'redirect', 'embed', 'widgets', 'plugins', 'button',
            'like.php', 'follow.php', 'comment', 'dialog', 'popup'
        ]
        
        url_lower = url.lower()
        
        if any(indicator in url_lower for indicator in false_positive_indicators):
            return False
        
        if 'youtube.com/redirect' in url_lower:
            return False
        
        if re.search(r'facebook\.com/\d{10,}', url_lower):
            return False
        
        if 'linkedin.com' in url_lower:
            linkedin_patterns = [
                r'linkedin\.com/company/[a-zA-Z0-9\-]+',
                r'linkedin\.com/in/[a-zA-Z0-9\-]+', 
                r'linkedin\.com/showcase/[a-zA-Z0-9\-]+',
                r'linkedin\.com/school/[a-zA-Z0-9\-]+',
                r'linkedin\.com/pages/[a-zA-Z0-9\-]+'
            ]
            if not any(re.search(pattern, url_lower) for pattern in linkedin_patterns):
                return False
        
        return True
    
    def extract_cloud_storage(self, text):
        """Extract cloud storage URLs"""
        cloud_links = {
            'aws_s3': re.findall(self.pattern_matcher.AWS_S3_PATTERN, text, re.IGNORECASE),
            'azure_blob': re.findall(self.pattern_matcher.AZURE_BLOB_PATTERN, text, re.IGNORECASE),
            'gcp_storage': re.findall(self.pattern_matcher.GCP_STORAGE_PATTERN, text, re.IGNORECASE)
        }
        return {k: list(set(v)) for k, v in cloud_links.items() if v}
    
    def extract_subdomains(self, urls):
        """Extract subdomains from URLs"""
        subdomains = set()
        for url in urls:
            try:
                parsed = urllib.parse.urlparse(url)
                extracted = tldextract.extract(parsed.netloc)
                if extracted.subdomain and extracted.domain and extracted.suffix:
                    full_domain = f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}"
                    if extracted.domain + '.' + extracted.suffix == self.base_domain:
                        subdomains.add(full_domain)
            except Exception:
                continue
        return list(subdomains)
    
    def extract_files(self, urls):
        """Extract file URLs"""
        files = {}
        for file_type, pattern in self.pattern_matcher.FILE_PATTERNS.items():
            matches = []
            for url in urls:
                if re.search(pattern, url, re.IGNORECASE):
                    matches.append(url)
            if matches:
                files[file_type] = list(set(matches))
        return files
    
    def extract_html_comments(self, html_content):
        """Extract HTML comments"""
        comments = re.findall(r'<!--(.*?)-->', html_content, re.DOTALL)
        filtered_comments = []
        for comment in comments:
            clean_comment = comment.strip()
            if (clean_comment and 
                len(clean_comment) > 5 and
                not clean_comment.startswith('[if') and
                'google' not in clean_comment.lower() and
                'facebook' not in clean_comment.lower()):
                filtered_comments.append(clean_comment)
        return filtered_comments
    
    def extract_js_sources(self, soup):
        """Extract JavaScript source URLs"""
        js_sources = []
        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                full_url = urllib.parse.urljoin(self.base_url, src)
                if URLUtils.is_valid_url(full_url):
                    js_sources.append(full_url)
        return list(set(js_sources))
    
    def extract_marketing_tags(self, soup, html_content):
        """Extract marketing tags from HTML"""
        tags = {}
        
        ga_patterns = [
            r'UA-\d{4,10}-\d{1,4}',
            r'GTM-[A-Z0-9]{4,10}',
            r'G-[A-Z0-9]{8,10}',
        ]
        
        for pattern in ga_patterns:
            matches = re.findall(pattern, html_content)
            valid_matches = [match for match in matches if len(match) > 6]
            if valid_matches:
                tags['google_analytics'] = list(set(valid_matches))
                for match in valid_matches:
                    ColorOutput.finding(f"Marketing tag (google_analytics): {match}")
        
        if soup.find('script', string=re.compile('googletagmanager', re.I)):
            tags['google_tag_manager'] = True
            ColorOutput.finding("Marketing tag (google_tag_manager): detected")
        
        if re.search(r'facebook\.com\/tr\/?', html_content, re.I):
            tags['facebook_pixel'] = True
            ColorOutput.finding("Marketing tag (facebook_pixel): detected")
        
        if re.search(r'hotjar', html_content, re.I):
            tags['hotjar'] = True
            ColorOutput.finding("Marketing tag (hotjar): detected")
        
        return tags
    
    def extract_login_pages(self, urls, soup):
        """Extract login page URLs"""
        login_indicators = [
            'login', 'signin', 'auth', 'authenticate', 'logon', 'signon',
            'password', 'credential', 'session', 'oauth', 'sso'
        ]
        
        login_urls = set()
        
        for url in urls:
            url_lower = url.lower()
            if any(indicator in url_lower for indicator in login_indicators):
                login_urls.add(url)
        
        for form in soup.find_all('form'):
            action = form.get('action', '').lower()
            if any(indicator in action for indicator in login_indicators):
                full_url = urllib.parse.urljoin(self.base_url, form.get('action', ''))
                if URLUtils.is_valid_url(full_url):
                    login_urls.add(full_url)
        
        return list(login_urls)
    
    def extract_interesting_findings(self, soup, response_text, url):
        """Extract interesting findings from page"""
        interesting = {}
        
        iframes = soup.find_all('iframe')
        if iframes:
            interesting['iframes'] = [urllib.parse.urljoin(url, iframe.get('src')) 
                                    for iframe in iframes if iframe.get('src')]
        
        try:
            json.loads(response_text)
            interesting['json_content'] = url
        except Exception:
            pass
        
        return interesting

# DNS Information Gathering (truncated, but all methods remain)
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

class DNSRecon:
    def __init__(self):
        if DNS_AVAILABLE:
            self.resolver = dns.resolver.Resolver()
            self.resolver.timeout = 5
            self.resolver.lifetime = 5
        else:
            self.resolver = None
    
    def gather_dns_info(self, domain):
        dns_info = {}
        if not self.resolver:
            return dns_info
            
        try:
            a_records = self.resolver.resolve(domain, 'A')
            dns_info['a_records'] = [str(record) for record in a_records]
            
            mx_records = self.resolver.resolve(domain, 'MX')
            dns_info['mx_records'] = [str(record.exchange) for record in mx_records]
            
            txt_records = self.resolver.resolve(domain, 'TXT')
            dns_info['txt_records'] = [str(record) for record in txt_records]
            
            ns_records = self.resolver.resolve(domain, 'NS')
            dns_info['ns_recards'] = [str(record) for record in ns_records]
            
            try:
                cname_records = self.resolver.resolve(domain, 'CNAME')
                dns_info['cname_records'] = [str(record) for record in cname_records]
            except Exception:
                dns_info['cname_records'] = []
                
        except Exception:
            pass
        
        return dns_info

class DNSDumpsterAutomation:
    def __init__(self):
        self.base_url = "https://dnsdumpster.com"
    
    def open_in_browser(self, domain):
        """Open DNSDumpster analysis in browser"""
        try:
            import webbrowser
            
            dnsdumpster_url = f"https://dnsdumpster.com/?q={domain}"
            ColorOutput.info(f"DNSDumpster: {dnsdumpster_url}")
            
            webbrowser.open(dnsdumpster_url)
            ColorOutput.success("DNSDumpster opened in browser")
            
            ColorOutput.dns("DNSDumpster provides comprehensive DNS reconnaissance including:")
            ColorOutput.dns("  • Domain IP addresses and hosting information")
            ColorOutput.dns("  • Subdomain enumeration")
            ColorOutput.dns("  • DNS record analysis (A, MX, TXT, NS, CNAME)")
            ColorOutput.dns("  • Network infrastructure mapping")
            
            ip_info = self.get_domain_ip_info(domain)
            if ip_info.get('primary_ip'):
                ColorOutput.finding(f"Domain IP Address: {ip_info['primary_ip']}")
            if ip_info.get('reverse_dns') and ip_info['reverse_dns'] != "Not available":
                ColorOutput.finding(f"Reverse DNS: {ip_info['reverse_dns']}")
                
        except ImportError:
            ColorOutput.info(f"DNSDumpster URL: https://dnsdumpster.com/?q={domain}")
    
    def get_domain_ip_info(self, domain):
        """Get domain IP information"""
        ip_info = {}
        
        try:
            ip_address = socket.gethostbyname(domain)
            ip_info['primary_ip'] = ip_address
            
            try:
                hostname = socket.gethostbyaddr(ip_address)
                ip_info['reverse_dns'] = hostname[0]
            except Exception:
                ip_info['reverse_dns'] = "Not available"
            
        except Exception as e:
            ip_info['error'] = f"Could not resolve domain IP: {e}"
        
        return ip_info

# WHOIS Lookup (truncated, but all methods remain)
try:
    import whois
    import whois.parser
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

class WHOISLookup:
    def __init__(self):
        self.last_error = None
    
    def get_whois_info(self, domain):
        """WHOIS lookup with comprehensive error handling"""
        whois_info = {}
        
        if not WHOIS_AVAILABLE:
            return whois_info
            
        try:
            ColorOutput.info(f"Performing WHOIS lookup for: {domain}")
            
            import socket
            socket.setdefaulttimeout(15)
            
            try:
                w = whois.whois(domain)
            except Exception:
                return whois_info
            
            if not w or not hasattr(w, 'domain_name'):
                return whois_info
            
            whois_data = {
                'registrar': self._safe_getattr(w, 'registrar'),
                'creation_date': self._safe_date_getattr(w, 'creation_date'),
                'expiration_date': self._safe_date_getattr(w, 'expiration_date'),
                'updated_date': self._safe_date_getattr(w, 'updated_date'),
                'name_servers': self._safe_list_getattr(w, 'name_servers'),
                'emails': self._safe_list_getattr(w, 'emails'),
                'org': self._safe_getattr(w, 'org'),
                'country': self._safe_getattr(w, 'country'),
                'state': self._safe_getattr(w, 'state'),
                'city': self._safe_getattr(w, 'city'),
                'address': self._safe_getattr(w, 'address'),
                'zipcode': self._safe_getattr(w, 'zipcode'),
                'name': self._safe_getattr(w, 'name'),
                'dnssec': self._safe_getattr(w, 'dnssec'),
                'status': self._safe_list_getattr(w, 'status')
            }
            
            whois_info = {k: v for k, v in whois_data.items() if v and v != 'Unknown' and v != []}
            
            if whois_info:
                ColorOutput.success(f"WHOIS lookup completed for {domain}")
                self._display_whois_results(domain, whois_info)
                
        except Exception:
            pass
        
        import socket
        socket.setdefaulttimeout(None)
        
        return whois_info
    
    def _safe_getattr(self, obj, attr_name, default='Unknown'):
        """Safely get attribute from WHOIS object"""
        try:
            value = getattr(obj, attr_name, default)
            if value is None:
                return default
            if isinstance(value, list) and not value:
                return default
            return value
        except Exception:
            return default
    
    def _safe_date_getattr(self, obj, attr_name):
        """Safely extract date from WHOIS object"""
        try:
            value = getattr(obj, attr_name, None)
            if not value:
                return 'Unknown'
            if isinstance(value, list):
                if value:
                    return str(value[0])
                return 'Unknown'
            return str(value)
        except Exception:
            return 'Unknown'
    
    def _safe_list_getattr(self, obj, attr_name):
        """Safely extract list from WHOIS object"""
        try:
            value = getattr(obj, attr_name, [])
            if not value:
                return []
            if isinstance(value, list):
                return [str(item) for item in value if item]
            return [str(value)]
        except Exception:
            return []
    
    def _display_whois_results(self, domain, whois_info):
        """Display WHOIS results"""
        ColorOutput.whois("=" * 60)
        ColorOutput.whois(f"WHOIS RESULTS FOR: {domain.upper()}")
        ColorOutput.whois("=" * 60)
        
        if whois_info.get('registrar'):
            ColorOutput.whois(f"Registrar: {whois_info['registrar']}")
        
        date_info = []
        if whois_info.get('creation_date'):
            date_info.append(f"Created: {whois_info['creation_date']}")
        if whois_info.get('expiration_date'):
            date_info.append(f"Expires: {whois_info['expiration_date']}")
        if whois_info.get('updated_date'):
            date_info.append(f"Updated: {whois_info['updated_date']}")
        
        if date_info:
            ColorOutput.whois("Domain Dates:")
            for date in date_info:
                ColorOutput.whois(f"   {date}")
        
        org_info = []
        if whois_info.get('org'):
            org_info.append(f"Organization: {whois_info['org']}")
        if whois_info.get('name'):
            org_info.append(f"Registrant: {whois_info['name']}")
        
        if org_info:
            ColorOutput.whois("Organization:")
            for info in org_info:
                ColorOutput.whois(f"   {info}")
        
        location_info = []
        if whois_info.get('country'):
            location_info.append(f"Country: {whois_info['country']}")
        if whois_info.get('state'):
            location_info.append(f"State: {whois_info['state']}")
        if whois_info.get('city'):
            location_info.append(f"City: {whois_info['city']}")
        
        if location_info:
            ColorOutput.whois("Location:")
            for loc in location_info:
                ColorOutput.whois(f"   {loc}")
        
        if whois_info.get('name_servers'):
            ColorOutput.whois("Name Servers:")
            for ns in whois_info['name_servers'][:5]:
                ColorOutput.whois(f"   {ns}")
        
        if whois_info.get('emails'):
            ColorOutput.whois("Contact Emails:")
            for email in whois_info['emails'][:3]:
                ColorOutput.whois(f"   {email}")
        
        if whois_info.get('status'):
            ColorOutput.whois("Domain Status:")
            for status in whois_info['status'][:3]:
                ColorOutput.whois(f"   {status}")
        
        if whois_info.get('dnssec'):
            ColorOutput.whois(f"DNSSEC: {whois_info['dnssec']}")
        
        ColorOutput.whois("=" * 60)
    
    def open_in_browser(self, domain):
        """Open WHOIS lookup in browser"""
        try:
            import webbrowser
            
            whois_services = [
                f"https://whois.domaintools.com/{domain}",
                f"https://whois.icann.org/en/lookup?name={domain}",
                f"https://www.whois.com/whois/{domain}",
                f"https://who.is/whois/{domain}"
            ]
            
            ColorOutput.info("Opening WHOIS lookup in browser services...")
            ColorOutput.info("Browser-based WHOIS lookups are more reliable than API-based queries")
            
            for service_url in whois_services[:2]:
                webbrowser.open(service_url)
                time.sleep(0.5)
            
            ColorOutput.success("WHOIS services opened in browser")
            
        except ImportError:
            ColorOutput.info("WHOIS Service URLs:")
            ColorOutput.info(f"   https://whois.domaintools.com/{domain}")
            ColorOutput.info(f"   https://whois.icann.org/en/lookup?name={domain}")

class WaybackMachine:
    def get_historical_data(self, domain):
        """Get historical data from Wayback Machine"""
        historical_data = {}
        
        try:
            wayback_url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&collapse=urlkey&limit=10"
            response = requests.get(wayback_url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if len(data) > 1:
                    historical_data['total_snapshots'] = len(data) - 1
                    historical_data['oldest_snapshot'] = data[1][1] if len(data) > 1 else None
                    historical_data['newest_snapshot'] = data[-1][1] if len(data) > 1 else None
                    historical_data['sample_urls'] = [entry[2] for entry in data[1:6]]
                    
        except Exception:
            pass
        
        return historical_data
    
    def open_in_browser(self, domain):
        """Open Wayback Machine in browser"""
        try:
            import webbrowser
            wayback_url = f"https://web.archive.org/web/*/{domain}"
            ColorOutput.info(f"Wayback Machine: {wayback_url}")
            
            webbrowser.open(wayback_url)
            ColorOutput.success("Wayback Machine opened in browser")
                
        except ImportError:
            ColorOutput.info(f"Wayback URL: https://web.archive.org/web/*/{domain}")

class AdvancedEmailHarvester:
    def harvest_emails(self, domain, crawled_urls):
        """Harvest emails from crawled content"""
        harvested_emails = set()
        
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        
        sample_urls = list(crawled_urls)[:10]
        
        for url in sample_urls:
            try:
                response = requests.get(url, timeout=10)
                emails = re.findall(email_pattern, response.text)
                for email in emails:
                    if (self._is_valid_email(email) and
                        not self._is_false_positive_email(email) and
                        self._is_likely_real_email(email)):
                        harvested_emails.add(email)
            except Exception:
                continue
        
        unique_emails = list(harvested_emails)
        
        if unique_emails:
            ColorOutput.success(f"Found {len(unique_emails)} unique email addresses:")
            for email in unique_emails:
                ColorOutput.finding(f"Email found: {email}")
        else:
            ColorOutput.info("No email addresses found")
        
        return unique_emails
    
    def _is_valid_email(self, email):
        """Validate email format"""
        email_lower = email.lower()
        
        false_positives = [
            r'noreply@', r'no-reply@', r'support@.*\.test', r'info@.*\.local',
            r'admin@.*\.local', r'root@localhost', r'postmaster@', r'webmaster@',
            r'example\.com', r'test\.com', r'domain\.com', r'sentry\.', r'wixpress\.com',
            r'^[a-f0-9]{32}@',
            r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}@',
        ]
        
        if any(re.search(pattern, email_lower) for pattern in false_positives):
            return False
        
        if (len(email) < 6 or 
            '..' in email or 
            email.count('@') != 1 or
            email.startswith('.') or 
            email.endswith('.')):
            return False
        
        return True
    
    def _is_false_positive_email(self, email):
        """Check for false positive email addresses"""
        false_positive_domains = [
            'example.com', 'domain.com', 'email.com', 'test.com',
            'yourdomain.com', 'sentry.io', 'w.org', 'github.com',
            'localhost', '127.0.0.1', 'your-email.com', 'company.com',
            'wixpress.com', 'sentry-next.wixpress.com', 'sentry.wixpress.com',
            'placeholder.com', 'fake.com', 'test.org', 'example.org'
        ]
        
        email_lower = email.lower()
        return any(domain in email_lower for domain in false_positive_domains)
    
    def _is_likely_real_email(self, email):
        """Check if email appears to be real"""
        email_lower = email.lower()
        
        real_patterns = [
            r'^[a-zA-Z]+\.[a-zA-Z]+@',
            r'^[a-zA-Z]+@',
            r'^[a-zA-Z][a-zA-Z0-9._-]*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        ]
        
        system_patterns = [
            r'^[a-f0-9]+@',
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}@',
            r'^[0-9]+@',
            r'^[a-z0-9]{32}@',
            r'@sentry\.',
            r'@.*\.sentry\.',
            r'@.*\.local$',
            r'@.*\.test$',
            r'@wixpress\.com$',
        ]
        
        if not any(re.search(pattern, email_lower) for pattern in real_patterns):
            return False
        
        if any(re.search(pattern, email_lower) for pattern in system_patterns):
            return False
        
        return True

class PDFExtractor:
    def open_pdf_search(self, domain):
        """Open PDF search in browser"""
        try:
            import webbrowser
            
            ColorOutput.info("PDF SEARCH AUTOMATION")
            
            searches = [
                f"site:{domain} filetype:pdf",
                f"site:{domain} ext:pdf", 
            ]
            
            ColorOutput.info(f"Opening PDF search for: {domain}")
            
            for search in searches:
                google_url = f"https://www.google.com/search?q={urllib.parse.quote(search)}"
                
                webbrowser.open(google_url)
                time.sleep(0.5)
            
            ColorOutput.success("PDF search opened in browser")
            
        except Exception:
            ColorOutput.info("Manual PDF Search URLs:")
            ColorOutput.info(f"Google: https://www.google.com/search?q=site:{domain}+filetype:pdf")

class TechnologyDetector:
    def __init__(self):
        # Technology patterns
        self.tech_patterns = {
            'WordPress': [
                r'wp-content', r'wp-includes', r'wordpress', r'/wp-json/', 
                r'wordpress', r'wp-admin', r'generator.*wordpress'
            ],
            'Joomla': [
                r'joomla', r'/media/jui/', r'/media/system/', r'generator.*joomla'
            ],
            'Drupal': [
                r'drupal', r'sites/all/', r'/misc/drupal', r'generator.*drupal'
            ],
            'Magento': [
                r'magento', r'/static/frontend/', r'/static/version'
            ],
            'Shopify': [
                r'shopify', r'cdn.shopify.com'
            ],
            'Nginx': [
                r'nginx', r'ngin[x|g]'
            ],
            'Apache': [
                r'apache', r'httpd', r'Apache'
            ],
            'IIS': [
                r'microsoft-iis', r'iis', r'x-powered-by.*iis'
            ],
            'PHP': [
                r'\.php', r'php', r'x-powered-by.*php', r'phppython'
            ],
            'Python': [
                r'python', r'django', r'flask', r'werkzeug', r'wsgi'
            ],
            'Node.js': [
                r'node\.js', r'express', r'npm', r'x-powered-by.*node'
            ],
            'Ruby': [
                r'ruby', r'rails', r'rack', r'passenger'
            ],
            'Java': [
                r'java', r'jsp', r'servlet', r'tomcat', r'jboss'
            ],
            'ASP.NET': [
                r'asp\.net', r'\.aspx', r'x-aspnet-version'
            ],
            'React': [
                r'react', r'react-dom', r'react\\.js'
            ],
            'Vue.js': [
                r'vue', r'vue\\.js', r'vue-router'
            ],
            'Angular': [
                r'angular', r'ng-', r'angular\.js'
            ],
            'jQuery': [
                r'jquery', r'jquery\\.js'
            ],
            'Bootstrap': [
                r'bootstrap', r'bootstrap\\.css'
            ],
            'Cloudflare': [
                r'cloudflare', r'cf-ray', r'__cfduid'
            ],
            'CloudFront': [
                r'cloudfront', r'aws.*cloudfront'
            ],
            'Akamai': [
                r'akamai', r'akamaiedge'
            ],
            'Google Analytics': [
                r'google-analytics', r'ga\.js', r'analytics\.js', r'gtag', r'ga\(', r'google.*analytics'
            ],
            'Google Tag Manager': [
                r'googletagmanager', r'gtm\.js'
            ],
            'Facebook Pixel': [
                r'facebook.*pixel', r'fbq\(', r'connect\.facebook\.net.*pixel'
            ],
            'Hotjar': [
                r'hotjar', r'hj.*js'
            ],
            'MySQL': [
                r'mysql', r'mysqli'
            ],
            'MongoDB': [
                r'mongodb', r'mongo'
            ],
            'PostgreSQL': [
                r'postgresql', r'postgres'
            ],
            'WooCommerce': [
                r'woocommerce', r'wc-'
            ],
            'PayPal': [
                r'paypal', r'ppobjects'
            ],
            'Stripe': [
                r'stripe', r'stripe\.js'
            ]
        }
    
    def detect_technologies(self, url):
        """Detect technologies used on website"""
        technologies = set()
        
        try:
            response = requests.get(url, timeout=15, verify=False)
            content = response.text.lower()
            headers = str(response.headers).lower()
            
            for tech, patterns in self.tech_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, headers, re.IGNORECASE):
                        technologies.add(tech)
                        break
            
            for tech, patterns in self.tech_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        technologies.add(tech)
                        break
            
            soup = BeautifulSoup(content, 'html.parser')
            
            generator = soup.find('meta', attrs={'name': 'generator'})
            if generator:
                generator_content = generator.get('content', '').lower()
                for tech, patterns in self.tech_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, generator_content, re.IGNORECASE):
                            technologies.add(tech)
            
            for script in soup.find_all('script', src=True):
                src = script['src'].lower()
                for tech, patterns in self.tech_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, src, re.IGNORECASE):
                            technologies.add(tech)
            
            for link in soup.find_all('link', href=True):
                href = link['href'].lower()
                for tech, patterns in self.tech_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, href, re.IGNORECASE):
                            technologies.add(tech)
                            
        except Exception:
            pass
        
        return list(technologies)

class BuiltWithAutomation:
    def open_in_browser(self, domain):
        """Open BuiltWith analysis in browser"""
        try:
            import webbrowser
            builtwith_url = f"https://builtwith.com/?{domain}"
            ColorOutput.info(f"BuiltWith: {builtwith_url}")
            
            webbrowser.open(builtwith_url)
            ColorOutput.success("BuiltWith opened in browser")
                
        except ImportError:
            ColorOutput.info(f"BuiltWith URL: https://builtwith.com/?{domain}")

class WebCrawler:
    def __init__(self, config, proxy=None):
        self.config = config
        self.proxy = proxy
        self.visited_urls = set()
        self.discovered_urls = set()
        self.session = self._create_session()
        self.pattern_matcher = PatternMatcher()
        self.image_downloader = None
        self.downloaded_images = []
    
    def _create_session(self):
        session = requests.Session()
        session.headers.update({'User-Agent': self.config.USER_AGENT})
        
        if self.proxy:
            if self.proxy.startswith('socks'):
                session.proxies = {'http': self.proxy, 'https': self.proxy}
            else:
                session.proxies = {'http': self.proxy, 'https': self.proxy}
        
        return session
    
    def enable_image_download(self, base_url, output_dir=None):
        """Enable image downloading"""
        self.image_downloader = ImageDownloader(self.config, base_url, output_dir)
        ColorOutput.info("Image downloading enabled")
        return self.image_downloader
    
    def fetch_url(self, url):
        """Fetch URL content"""
        try:
            if URLUtils.should_skip_url(url):
                return None, None, None
                
            response = self.session.get(url, timeout=self.config.TIMEOUT)
            response.raise_for_status()
            return response.text, response.headers, response.url
        except Exception:
            return None, None, None
    
    def discover_urls(self, start_url):
        """Discover URLs from robots.txt, sitemap, and page content"""
        discovered = set()
        
        robots_url = urllib.parse.urljoin(start_url, '/robots.txt')
        robots_urls = self._parse_robots_txt(robots_url)
        discovered.update(robots_urls)
        
        sitemap_urls = self._parse_sitemap(start_url)
        discovered.update(sitemap_urls)
        
        initial_urls = self._extract_urls_from_page(start_url)
        discovered.update(initial_urls)
        
        return discovered
    
    def _parse_robots_txt(self, robots_url):
        """Parse robots.txt for URLs"""
        urls = set()
        try:
            response = self.session.get(robots_url, timeout=self.config.TIMEOUT)
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    line = line.strip()
                    if line.startswith('Allow:') or line.startswith('Disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            full_url = urllib.parse.urljoin(robots_url, path)
                            if URLUtils.is_valid_url(full_url) and not URLUtils.should_skip_url(full_url):
                                urls.add(full_url)
                if urls:
                    ColorOutput.success(f"Found {len(urls)} URLs in robots.txt")
        except Exception:
            pass
        return urls
    
    def _parse_sitemap(self, base_url):
        """Parse sitemap.xml for URLs"""
        urls = set()
        sitemap_urls = [
            urllib.parse.urljoin(base_url, '/sitemap.xml'),
            urllib.parse.urljoin(base_url, '/sitemap_index.xml'),
            urllib.parse.urljoin(base_url, '/sitemap/')
        ]
        
        for sitemap_url in sitemap_urls:
            try:
                response = self.session.get(sitemap_url, timeout=self.config.TIMEOUT)
                if response.status_code == 200:
                    try:
                        soup = BeautifulSoup(response.content, 'xml')
                    except Exception:
                        soup = BeautifulSoup(response.content, 'lxml-xml')
                    
                    for loc in soup.find_all('loc'):
                        url = loc.text.strip()
                        if URLUtils.is_valid_url(url) and not URLUtils.should_skip_url(url):
                            urls.add(url)
                    if urls:
                        ColorOutput.success(f"Found {len(urls)} URLs in sitemap")
            except Exception:
                continue
        
        return urls
    
    def _extract_urls_from_page(self, url):
        """Extract URLs from page content"""
        urls = set()
        content, headers, final_url = self.fetch_url(url)
        
        if content:
            soup = BeautifulSoup(content, 'html.parser')
            
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urllib.parse.urljoin(final_url, href)
                if URLUtils.is_valid_url(full_url) and not URLUtils.should_skip_url(full_url):
                    urls.add(full_url)
        
        return urls
    
    def crawl(self, start_url, max_pages=None, max_depth=None, download_images=True):
        """Main crawling function"""
        if max_pages is None:
            max_pages = self.config.MAX_PAGES
        if max_depth is None:
            max_depth = self.config.MAX_DEPTH
        
        if download_images and self.config.DOWNLOAD_IMAGES:
            self.enable_image_download(start_url)
        
        queue = [(start_url, 0)]
        all_findings = {
            'emails': set(),
            'social_media': {},
            'cloud_storage': {},
            'subdomains': set(),
            'files': {},
            'login_pages': set(),
            'crawled_links': set(),
            'html_comments': set(),
            'js_sources': set(),
            'marketing_tags': {},
            'interesting_findings': {},
            'images': []
        }
        
        ColorOutput.info("Starting URL discovery...")
        discovered_urls = self.discover_urls(start_url)
        for url in discovered_urls:
            if url not in self.visited_urls and not URLUtils.should_skip_url(url):
                queue.append((url, 1))
        
        processed_count = 0
        while queue and len(self.visited_urls) < max_pages and processed_count < 50:
            url, depth = queue.pop(0)
            
            if url in self.visited_urls or depth > max_depth or URLUtils.should_skip_url(url):
                continue
            
            ColorOutput.info(f"Crawling: {url} (Depth: {depth})")
            
            content, headers, final_url = self.fetch_url(url)
            if content:
                self.visited_urls.add(url)
                all_findings['crawled_links'].add(final_url)
                
                extractor = DataExtractor(start_url)
                soup = BeautifulSoup(content, 'html.parser')
                
                self._update_findings(all_findings, extractor, content, soup, final_url)
                
                if self.image_downloader:
                    page_images = self.image_downloader.download_images_from_page(soup, final_url)
                    all_findings['images'].extend(page_images)
                
                if depth < max_depth:
                    new_urls = self._extract_urls_from_page(url)
                    for new_url in new_urls:
                        if (new_url not in self.visited_urls and 
                            new_url not in [u for u, d in queue] and 
                            len(self.visited_urls) < max_pages and
                            not URLUtils.should_skip_url(new_url)):
                            queue.append((new_url, depth + 1))
                
                time.sleep(self.config.CRAWL_DELAY)
                processed_count += 1
        
        extractor = DataExtractor(start_url)
        all_findings['subdomains'] = extractor.extract_subdomains(all_findings['crawled_links'])
        
        if self.image_downloader and all_findings['images']:
            self.image_downloader.save_metadata()
            self.image_downloader.generate_html_gallery()
            self.image_downloader.print_summary()
        
        return self._format_findings(all_findings)
    
    def _update_findings(self, findings, extractor, content, soup, url):
        """Update findings with new extracted data"""
        emails = extractor.extract_emails(content)
        if emails:
            findings['emails'].update(emails)
        
        social = extractor.extract_social_media(content)
        for platform, links in social.items():
            if platform not in findings['social_media']:
                findings['social_media'][platform] = set()
            findings['social_media'][platform].update(links)
            for link in links:
                ColorOutput.finding(f"Social media ({platform}): {link}")
        
        cloud = extractor.extract_cloud_storage(content)
        for service, links in cloud.items():
            if service not in findings['cloud_storage']:
                findings['cloud_storage'][service] = set()
            findings['cloud_storage'][service].update(links)
            for link in links:
                ColorOutput.finding(f"Cloud storage ({service}): {link}")
        
        files = extractor.extract_files([url])
        for file_type, file_urls in files.items():
            if file_type not in findings['files']:
                findings['files'][file_type] = set()
            findings['files'][file_type].update(file_urls)
            for file_url in file_urls:
                ColorOutput.finding(f"File ({file_type}): {file_url}")
        
        comments = extractor.extract_html_comments(content)
        if comments:
            findings['html_comments'].update(comments)
            for comment in comments[:3]:
                if len(comment) > 100:
                    ColorOutput.finding(f"HTML comment: {comment[:100]}...")
                else:
                    ColorOutput.finding(f"HTML comment: {comment}")
        
        js_sources = extractor.extract_js_sources(soup)
        if js_sources:
            findings['js_sources'].update(js_sources)
        
        tags = extractor.extract_marketing_tags(soup, content)
        for tag_type, value in tags.items():
            if tag_type not in findings['marketing_tags']:
                findings['marketing_tags'][tag_type] = set()
            if isinstance(value, list):
                findings['marketing_tags'][tag_type].update(value)
            else:
                findings['marketing_tags'][tag_type].add(value)
        
        interesting = extractor.extract_interesting_findings(soup, content, url)
        for finding_type, value in interesting.items():
            if finding_type not in findings['interesting_findings']:
                findings['interesting_findings'][finding_type] = set()
            if isinstance(value, list):
                findings['interesting_findings'][finding_type].update(value)
                for val in value:
                    ColorOutput.finding(f"Interesting finding ({finding_type}): {val}")
            else:
                findings['interesting_findings'][finding_type].add(value)
                ColorOutput.finding(f"Interesting finding ({finding_type}): {value}")
    
    def _format_findings(self, findings):
        """Convert sets to lists for JSON output"""
        formatted = {}
        for key, value in findings.items():
            if isinstance(value, set):
                formatted[key] = list(value)
            elif isinstance(value, dict):
                formatted[key] = {}
                for subkey, subvalue in value.items():
                    if isinstance(subvalue, set):
                        formatted[key][subkey] = list(subvalue)
                    else:
                        formatted[key][subkey] = subvalue
            else:
                formatted[key] = value
        return formatted

class WebReconPro:
    def __init__(self, config):
        self.config = config
        self.results = {}
    
    def run_advanced_reconnaissance(self, start_url, max_pages=None, max_depth=None, output_file=None,
                                  enable_dns=True, enable_whois=True, enable_wayback=True, 
                                  enable_builtwith=True, enable_dnsdumpster=True,
                                  download_images=True):
        """Advanced reconnaissance with all features"""
        ColorOutput.info(f"Starting WebRecon Pro against: {start_url}")
        ColorOutput.info(f"Timestamp: {datetime.now().isoformat()}")
        
        if not URLUtils.is_valid_url(start_url):
            ColorOutput.info("Invalid URL provided")
            return
        
        os.makedirs(self.config.OUTPUT_DIR, exist_ok=True)
        
        proxy = self.config.HTTP_PROXY or self.config.SOCKS_PROXY
        
        crawler = None
        try:
            crawler = WebCrawler(self.config, proxy=proxy)
            
            ColorOutput.info("Starting web crawling...")
            crawl_results = crawler.crawl(start_url, max_pages, max_depth, download_images=download_images)
            self.results.update(crawl_results)
            
            domain = URLUtils.get_domain(start_url)
            
            if enable_dnsdumpster:
                ColorOutput.info("DNSDumpster domain IP analysis...")
                dnsdumpster = DNSDumpsterAutomation()
                domain_ip_info = dnsdumpster.get_domain_ip_info(domain)
                if domain_ip_info:
                    self.results['domain_ip_info'] = domain_ip_info
                dnsdumpster.open_in_browser(domain)
            
            if enable_dns:
                ColorOutput.info("Performing DNS reconnaissance...")
                dns_recon = DNSRecon()
                dns_info = dns_recon.gather_dns_info(domain)
                if dns_info:
                    self.results['dns_info'] = dns_info
                    ColorOutput.success("DNS reconnaissance completed")
            
            if enable_whois:
                ColorOutput.info("Performing WHOIS lookup...")
                whois_lookup = WHOISLookup()
                whois_info = whois_lookup.get_whois_info(domain)
                if whois_info:
                    self.results['whois_info'] = whois_info
                    ColorOutput.success("WHOIS lookup completed")
                else:
                    ColorOutput.info("Using browser-based WHOIS lookup")
                
                whois_lookup.open_in_browser(domain)
            
            if enable_wayback:
                ColorOutput.info("Wayback Machine historical analysis...")
                wayback = WaybackMachine()
                self.results['wayback_data'] = wayback.get_historical_data(domain)
                wayback.open_in_browser(domain)
            
            ColorOutput.info("Performing advanced email harvesting...")
            email_harvester = AdvancedEmailHarvester()
            additional_emails = email_harvester.harvest_emails(domain, self.results['crawled_links'])
            all_emails = set(self.results.get('emails', []) + additional_emails)
            self.results['emails'] = list(all_emails)
            
            pdf_extractor = PDFExtractor()
            pdf_extractor.open_pdf_search(domain)
            
            ColorOutput.info("Performing technology detection...")
            tech_detector = TechnologyDetector()
            technologies = tech_detector.detect_technologies(start_url)
            
            self.results['technologies'] = {
                'detected': technologies
            }
            
            if technologies:
                ColorOutput.success(f"Technologies detected: {len(technologies)}")
                for tech in technologies:
                    ColorOutput.finding(f"Technology: {tech}")
            else:
                ColorOutput.info("No technologies detected")
            
            if enable_builtwith:
                ColorOutput.info("BuiltWith technology analysis...")
                builtwith = BuiltWithAutomation()
                builtwith.open_in_browser(domain)
            
            self._generate_report(output_file, domain)
            
            ColorOutput.success("Advanced reconnaissance completed successfully!")
            
        except Exception as e:
            ColorOutput.info(f"Reconnaissance completed with notes: {str(e)[:100]}")
        finally:
            if crawler:
                pass
    
    def _generate_report(self, output_file=None, domain=None):
        """Generate comprehensive report"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if domain:
                safe_domain = "".join(c for c in domain if c.isalnum() or c in ('-', '_')).rstrip()
                output_file = f"{self.config.OUTPUT_DIR}/webrecon_{safe_domain}_{timestamp}.json"
            else:
                output_file = f"{self.config.OUTPUT_DIR}/webrecon_report_{timestamp}.json"
        
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            
            self._print_summary()
            
            ColorOutput.success(f"Full report saved to: {output_file}")
        except Exception as e:
            ColorOutput.info(f"Could not save report: {str(e)[:100]}")
            self._print_summary()
    
    def _print_summary(self):
        """Print reconnaissance summary"""
        ColorOutput.info("\n" + "="*60)
        ColorOutput.info("WEBRECON PRO - RECONNAISSANCE SUMMARY")
        ColorOutput.info("="*60)
        
        stats = {
            'Crawled Links': len(self.results.get('crawled_links', [])),
            'Valid Emails Found': len(self.results.get('emails', [])),
            'Subdomains Found': len(self.results.get('subdomains', [])),
            'Social Media Links': sum(len(v) for v in self.results.get('social_media', {}).values()),
            'Cloud Storage Links': sum(len(v) for v in self.results.get('cloud_storage', {}).values()),
            'Files Found': sum(len(v) for v in self.results.get('files', {}).values()),
            'Login Pages': len(self.results.get('login_pages', [])),
            'HTML Comments': len(self.results.get('html_comments', [])),
            'JS Sources': len(self.results.get('js_sources', [])),
            'Technologies Detected': len(self.results.get('technologies', {}).get('detected', [])),
            'Images Downloaded': len(self.results.get('images', []))
        }
        
        for category, count in stats.items():
            if count > 0:
                ColorOutput.finding(f"{category}: {count}")
            else:
                ColorOutput.info(f"{category}: {count}")
        
        if self.results.get('domain_ip_info'):
            ColorOutput.info("\nDOMAIN IP INFORMATION:")
            ip_info = self.results['domain_ip_info']
            if ip_info.get('primary_ip'):
                ColorOutput.finding(f"  Primary IP: {ip_info['primary_ip']}")
            if ip_info.get('reverse_dns') and ip_info['reverse_dns'] != "Not available":
                ColorOutput.finding(f"  Reverse DNS: {ip_info['reverse_dns']}")
        
        if self.results.get('dns_info'):
            ColorOutput.info("\nDNS INFORMATION:")
            for record_type, records in self.results['dns_info'].items():
                if records:
                    ColorOutput.finding(f"  {record_type.upper()}: {', '.join(records)}")
        
        if self.results.get('whois_info'):
            ColorOutput.info("\nWHOIS INFORMATION:")
            whois_info = self.results['whois_info']
            if whois_info.get('registrar'):
                ColorOutput.finding(f"  Registrar: {whois_info['registrar']}")
            if whois_info.get('creation_date'):
                ColorOutput.finding(f"  Created: {whois_info['creation_date']}")
            if whois_info.get('org'):
                ColorOutput.finding(f"  Organization: {whois_info['org']}")
            if whois_info.get('country'):
                ColorOutput.finding(f"  Country: {whois_info['country']}")
        
        if self.results.get('emails'):
            ColorOutput.info("\nEMAILS FOUND:")
            for email in self.results['emails']:
                ColorOutput.finding(f"  {email}")
        
        if self.results.get('social_media', {}).get('linkedin'):
            ColorOutput.info("\nLINKEDIN URLS FOUND:")
            for linkedin_url in self.results['social_media']['linkedin']:
                ColorOutput.finding(f"  LinkedIn: {linkedin_url}")
        
        if self.results.get('technologies', {}).get('detected'):
            ColorOutput.info("\nTECHNOLOGY SUMMARY:")
            techs = self.results['technologies']['detected']
            ColorOutput.finding(f"  Detected: {', '.join(techs)}")
        
        if self.results.get('images'):
            ColorOutput.info("\nIMAGE DOWNLOAD SUMMARY:")
            total_size = sum(img.get('file_size', 0) for img in self.results['images'])
            ColorOutput.image(f"  Total Images Downloaded: {len(self.results['images'])}")
            ColorOutput.image(f"  Total Size: {self._format_file_size(total_size)}")
            ColorOutput.image("  Sample downloaded images:")
            for img in self.results['images'][:3]:
                ColorOutput.image(f"    - {img.get('filename', 'Unknown')} ({self._format_file_size(img.get('file_size', 0))})")
    
    def _format_file_size(self, size_bytes):
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"

def display_usage():
    """Display usage information"""
    print(f"""
{Fore.CYAN}WebRecon Pro - Advanced OSINT Web Reconnaissance Tool
{Fore.YELLOW}Usage Guide:{Style.RESET_ALL}

{Fore.GREEN}Basic Usage:{Style.RESET_ALL}
  python3 webrecon_pro.py https://example.com

{Fore.GREEN}Advanced Options:{Style.RESET_ALL}
  --max-pages NUM        Maximum pages to crawl (default: 100)
  --max-depth NUM        Maximum crawl depth (default: 2)
  --output FILE          Custom output file path
  --proxy URL            HTTP/SOCKS proxy

{Fore.GREEN}Feature Control:{Style.RESET_ALL}
  --no-dns               Disable DNS reconnaissance
  --no-whois             Disable WHOIS lookup
  --no-wayback           Disable Wayback Machine
  --no-builtwith         Disable BuiltWith technology analysis
  --no-dnsdumpster       Disable DNSDumpster domain IP analysis
  --no-images            Disable image downloading

{Fore.GREEN}Examples:{Style.RESET_ALL}
  python3 webrecon_pro.py https://example.com
  python3 webrecon_pro.py https://example.com --proxy socks5://127.0.0.1:9050 --output results.json
  python3 webrecon_pro.py https://example.com --no-images
    """)

def main():
    banner = f"""
{Fore.CYAN}
 █████   ███   █████          █████     ███████████                                        
░░███   ░███  ░░███          ░░███     ░░███░░░░░███                                       
 ░███   ░███   ░███   ██████  ░███████  ░███    ░███   ██████   ██████   ██████  ████████  
 ░███   ░███   ░███  ███░░███ ░███░░███ ░██████████   ███░░███ ███░░███ ███░░███ ░░███░░███ 
 ░░███  █████  ███  ░███████  ░███ ░███ ░███░░░░░███ ░███████ ░███ ░░░ ░███ ░███  ░███ ░███ 
  ░░░█████░█████░   ░███░░░   ░███ ░███ ░███    ░███ ░███░░░  ░███  ███░███ ░███  ░███ ░███ 
    ░░███ ░░███     ░░██████  ████████  █████   █████░░██████ ░░██████ ░░██████  ████ █████
     ░░░   ░░░       ░░░░░░  ░░░░░░░░  ░░░░░   ░░░░░  ░░░░░░   ░░░░░░   ░░░░░░  ░░░░ ░░░░░ 
                                                                                           
{Fore.YELLOW}                          Advanced OSINT Web Reconnaissance Tool
{Fore.WHITE}                          Author: D4rk_Intel | Project: OSINT Reconnaissance Tool
{Style.RESET_ALL}
    """
    
    print(banner)
    
    parser = argparse.ArgumentParser(
        description='WebRecon Pro - Advanced OSINT Web Reconnaissance Tool',
        add_help=False
    )
    
    parser.add_argument('url', nargs='?', help='Target URL for reconnaissance')
    parser.add_argument('--max-pages', type=int, default=100, help='Maximum pages to crawl (default: 100)')
    parser.add_argument('--max-depth', type=int, default=2, help='Maximum crawl depth (default: 2)')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--proxy', help='HTTP/SOCKS proxy (overrides config)')
    parser.add_argument('--no-dns', action='store_true', help='Disable DNS reconnaissance')
    parser.add_argument('--no-whois', action='store_true', help='Disable WHOIS lookup')
    parser.add_argument('--no-wayback', action='store_true', help='Disable Wayback Machine')
    parser.add_argument('--no-builtwith', action='store_true', help='Disable BuiltWith automation')
    parser.add_argument('--no-dnsdumpster', action='store_true', help='Disable DNSDumpster domain IP analysis')
    parser.add_argument('--no-images', action='store_true', help='Disable image downloading')
    parser.add_argument('-h', '--help', action='store_true', help='Show this help message and exit')
    
    args = parser.parse_args()
    
    if args.help or not args.url:
        display_usage()
        return
    
    config = Config()
    if args.proxy:
        if args.proxy.startswith('socks'):
            config.SOCKS_PROXY = args.proxy
        else:
            config.HTTP_PROXY = args.proxy
    
    config.MAX_PAGES = args.max_pages
    config.MAX_DEPTH = args.max_depth
    config.DOWNLOAD_IMAGES = not args.no_images
    
    recon = WebReconPro(config)
    recon.run_advanced_reconnaissance(
        start_url=args.url,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        output_file=args.output,
        enable_dns=not args.no_dns,
        enable_whois=not args.no_whois,
        enable_wayback=not args.no_wayback,
        enable_builtwith=not args.no_builtwith,
        enable_dnsdumpster=not args.no_dnsdumpster,
        download_images=not args.no_images
    )

if __name__ == '__main__':
    main()