# This package will contain the spiders of your Scrapy project
#
# Please refer to the documentation for information on how to create and manage
# your spiders.
import re
from urllib.parse import urlparse
import scrapy
from scrapy.crawler import CrawlerProcess
from scrapy import Selector

plugin_list = []


class CollectLinksAndComments(scrapy.Spider):
    """Spider for collecting WordPress plugin information."""
    name = "scrapy_the_spider"
    
    def __init__(self, url=None, *args, **kwargs):
        super(CollectLinksAndComments, self).__init__(*args, **kwargs)
        if url:
            self.url = url.rstrip('/')
            # Extract domain from URL
            parsed_url = urlparse(url)
            self.allowed_domains = [parsed_url.netloc]
            self.start_urls = [url]
            print(f"Allowed Domains: {self.allowed_domains}\nStart Sites: {url}")

    def parse(self, response):
        content = Selector(response=response)
        src_text = content.xpath("//script/@src").extract()
        href_text = content.xpath("//a/@href").extract()
        
        for i in href_text:
            yield response.follow(i, callback=self.parse)
            
        extract_plugins(src_text, href_text)


def extract_plugins(*args: list):
    """Extract plugin references from lists of URLs."""
    for lst in args:
        for element in lst:
            if re.search(r"plugin", element):
                plugin_list.append(element)


def get_plugin_name(plugin_list: list):
    """Extract plugin names and versions from URLs."""
    link_pattern = r"/plugins/(.*?)/"
    version_pattern = r"ver=([\d.\d]*)"
    
    for index, link in enumerate(plugin_list, 0):
        if re.search(link_pattern, link):
            plugin_match = re.search(link_pattern, link)
            version_match = re.search(version_pattern, link)
            if plugin_match and version_match:
                plugin_list[index] = f"{plugin_match.group(1)}:{version_match.group(1)}"
    
    return list(set(plugin_list))


def start_crawler(url=None):
    """
    Start the crawler for a given WordPress site.
    
    Args:
        url (str): Target WordPress site URL
        
    Returns:
        list: List of found plugins with their versions
    """
    if not url:
        raise ValueError("URL is required")
        
    # Clear any previous results
    plugin_list.clear()
    
    # Create new process and crawl with settings to prevent output noise
    process = CrawlerProcess({
        'LOG_ENABLED': False,
        'ROBOTSTXT_OBEY': False,
        'USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    })
    process.crawl(CollectLinksAndComments, url=url)
    process.start(stop_after_crawl=True)
    
    return get_plugin_name(plugin_list)


if __name__ == "__main__":
    # This is just for testing the crawler directly
    test_url = "http://127.0.0.1:31337/"
    plugins = start_crawler(test_url)
    print("\nFound Plugins:")
    for plugin in plugins:
        print(plugin)