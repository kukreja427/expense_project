from pydantic import BaseModel, Field

class Destination(BaseModel):
    name: str
    imageUrl: str
    rating: float
    description: str = ""
    detail_facilities: str = ""
    price: float = 0.0

    class Config:
        schema_extra = {
            "example": {
                "name": "Niagara Falls",
                "imageUrl": "https://example.com/niagara_falls.png",
                "rating": 4.1,
                "description": "A breathtaking natural wonder located on the border of Ontario, Canada, and New York, USA.",
                "detail_facilities": "Department of Information Technology",
                "price": 100
            }
        }
