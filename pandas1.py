import pandas1 as pd
import matplotlib.pyplot as plt
import seaborn as sns
file_path = '../events.json'
df = pd.read_json(file_path)

print("Первые строки датафрейма:")
print(df.head())

if 'signature' not in df.columns:
    raise ValueError("В данных нет поля 'signature'")

sig_counts = df['signature'].value_counts()
print("\nРаспределение событий по типам (signature):")
print(sig_counts)

sig_counts_df = sig_counts.reset_index()
sig_counts_df.columns = ['signature', 'count']

print("\nТаблица распределения:")
print(sig_counts_df)

sns.set(style="whitegrid")

plt.figure(figsize=(12, 6))

sns.barplot(
    data=sig_counts_df,
    x='count',
    y='signature'
)

plt.title('Распределение типов событий информационной безопасности по полю "signature"')
plt.xlabel('Количество событий')
plt.ylabel('Тип события (signature)')
plt.tight_layout()
plt.show()
