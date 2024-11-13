import pandas as pd
from collections import defaultdict

# File paths for honeypot data and wordlists
honeypot_files = {
    'H1': 'Dynamic H1.csv',
    'H2': 'Dynamic H2.csv',
    'H3': 'Password Tagcloud H3.csv'
}
wordlist_files = [
    '2020-200_most_used_passwords.txt',
    '2023-200_most_used_passwords.txt',
    'rockyou.txt',
    'xato-net-10-million-passwords-1000000.txt'
]

# Mapping of short source identifiers to full names with regions
source_mapping = {
    'H1': 'Honeypot 1 [GCP - US Central]',
    'H2': 'Honeypot 2 [GCP - Netherlands West4]',
    'H3': 'Honeypot 3 [Digital Ocean - London]'
}

# Function to load honeypot data from CSV files
def load_honeypot_passwords(file_path, source):
    df = pd.read_csv(file_path)
    passwords = {}
    for _, row in df.iterrows():
        password, count = row.iloc[0], row.iloc[1]  # Use iloc for positional access
        passwords[password] = {'count': int(count), 'source': source}
    return passwords

# Load all honeypot password data
honeypot_passwords = {}
for source, file_path in honeypot_files.items():
    honeypot_passwords.update(load_honeypot_passwords(file_path, source))

# Load all wordlists into a set for fast lookup (with UTF-8 encoding)
wordlist_set = set()
for wordlist_path in wordlist_files:
    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
        wordlist_set.update(line.strip() for line in f)

# Find unique passwords not in wordlists
unique_passwords = defaultdict(lambda: {'count': 0, 'sources': []})

for password, details in honeypot_passwords.items():
    if password not in wordlist_set:
        unique_passwords[password]['count'] += details['count']
        # Use full form of the source from source_mapping
        unique_passwords[password]['sources'].append(source_mapping[details['source']])

# Convert unique passwords to a DataFrame
unique_passwords_df = pd.DataFrame([
    {'Password': pwd, 'Count': details['count'], 'Sources': ', '.join(details['sources'])}
    for pwd, details in unique_passwords.items()
])

# Save to an Excel file
unique_passwords_df.to_excel('unique_honeypot_passwords.xlsx', index=False)

print("Unique passwords saved to 'unique_honeypot_passwords.xlsx'")
