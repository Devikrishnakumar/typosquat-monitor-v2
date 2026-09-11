from src.storage.db import init_db, insert_candidate, get_all_candidates

init_db()
insert_candidate("flipkaret.com", "flipkart.com")
insert_candidate("fli8pkart.com", "flipkart.com")

rows = get_all_candidates()
for row in rows:
    print(row)
