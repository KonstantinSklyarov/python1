import requests

url = "https://jsonplaceholder.typicode.com/posts"

response = requests.get(url)
posts = response.json()

print("Первые 5 постов:\n")

for post in posts[:5]:
    print(f"Заголовок: {post['title']}")
    print(f"Текст: {post['body']}")
    print("-" * 40)
