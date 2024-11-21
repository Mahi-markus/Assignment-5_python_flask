# destination_service/models.py

class Destination:
    def __init__(self, id, name, description, location, price_per_night):
        self.id = id
        self.name = name
        self.description = description
        self.location = location
        self.price_per_night = price_per_night

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "location": self.location,
            "price_per_night": self.price_per_night,
        }
