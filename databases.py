import platform
from configparser import SectionProxy
from typing import List, Dict

from pymongo import MongoClient


class IDatabase:
    TYPE = NotImplemented

    def upload_document(self, document: dict):
        pass

    def upload_documents(self, documents: List[Dict]):
        pass


class MongoDB(IDatabase):
    TYPE = "mongodb"

    def __init__(self, url: str, db: str, interface: str, collection: str = None):
        if collection is None:
            collection = f"{platform.node()}.{interface}"

        client = MongoClient(url)
        self.interface = interface
        self.collection = client[db][collection]

    def upload_document(self, document: dict):
        self.collection.insert_one(document)

    def upload_documents(self, documents: List[Dict]):
        self.collection.insert_many(documents)


def init_db(config: SectionProxy, interface: str) -> IDatabase:
    if config["type"] == MongoDB.TYPE:
        return MongoDB(
            url=config["url"],
            db=config["db"],
            interface=interface,
            collection=config.get("collection", None),
        )

    raise NameError(f"Couldn't identify database type '{config['type']}'")
