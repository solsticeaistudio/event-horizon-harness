with open('src/event_horizon/key_management.py', 'r') as f:
    content = f.read()

import re
# Find the KeyManager's get_key method (the first one)
match = re.search(r'def get_key\(self, key_id_str: str\) -> KeyMetadata \| None:', content)
if match:
    method_start = match.start()
    # Find next method
    next_method = content.find('\n    def ', method_start + 1)
    if next_method == -1:
        next_method = content.find('\nclass ', method_start)
    
    print(f'Inserting at position {next_method}')
    print(f'Next method starts: {content[next_method:next_method+50]}')
    
    get_provenance_code = '''    def get_provenance(self, key_id_str: str) -> list[dict]:
        """Get provenance records for a key."""
        rows = self._db.execute(
            "SELECT * FROM key_provenance WHERE key_id = ? ORDER BY timestamp",
            (key_id_str,)
        ).fetchall()
        return [
            {
                'key_id': row[0],
                'action': row[1],
                'actor': row[2],
                'timestamp': row[3],
                'details_json': row[4],
                'signature': row[5],
            }
            for row in rows
        ]

'''
    content = content[:next_method] + get_provenance_code + content[next_method:]
    
    with open('src/event_horizon/key_management.py', 'w') as f:
        f.write(content)
    
    print('get_provenance inserted successfully!')
else:
    print('Could not find get_key method')