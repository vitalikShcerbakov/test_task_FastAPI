from fastapi import Depends, FastAPI
from fastapi.security import OAuth2PasswordBearer

from typing_extensions import Annotated
from pydantic import BaseModel


app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class Data(BaseModel):
    value: str


database = [Data(value='test')]




@app.get("/path/")
async def read_items(token: Annotated[str, Depends(oauth2_scheme)]):
    return {"token": token}


@app.post("/item/")
async def add_item(data: Data):
    database.append(data)
    return data


@app.get("/items/")
async def read_item_all():
    return database
