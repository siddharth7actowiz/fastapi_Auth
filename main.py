import uvicorn

def main():
    print("Hello from authentication-authorization-fastapi!")
    uvicorn.run("app.app:app", host="localhost", port=8000, reload=True)


if __name__ == "__main__":
    main()
