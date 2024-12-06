# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html
import scrapy


class LinksAndCommentsItem(scrapy.Item):
    src = scrapy.Field(default=[])
    href = scrapy.Field(default=[])
    comment = scrapy.Field(default=[])
