from fastapi import FastAPI

from pydantic import BaseModel


app = FastAPI()


class Data(BaseModel):
    value: str


database = [Data(value='test')]


@app.post("/item/")
async def add_item(data: Data):
    database.append(data)
    return data


@app.get("/items/")
async def read_item_all():
    return database
