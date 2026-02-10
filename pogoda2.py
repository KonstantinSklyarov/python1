import requests

API_KEY = "ключ"
city = input("Введите название города: ")

url = "https://api.openweathermap.org/data/2.5/weather"

params = {
    "q": city,
    "appid": API_KEY,
    "units": "metric",
    "lang": "ru"
}

response = requests.get(url, params=params)
data = response.json()

if response.status_code == 200:
    temperature = data["main"]["temp"]
    description = data["weather"][0]["description"]

    print(f"Город: {city}")
    print(f"Температура: {temperature} °C")
    print(f"Погода: {description}")
else:
    print("Ошибка при получении данных о погоде")
    print(data)