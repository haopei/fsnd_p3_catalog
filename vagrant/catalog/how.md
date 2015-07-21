# P3 Catalog

A catalog project where users may log in using oauth and add/delete/edit items.


# Using
 - flask
 - oauth authentication
 - various HTTP methods
 - CRUD

# Expectations
 [] app provides a list of items from a variety of categories
 [] user registration and authentication system
 [] Selecting a category shows the items (and count) in that category (http://localhost:8000/catalog/Snowboarding/items)
 [] Selecting a specific item shows its specific information (http://localhost:8000/catalog/Snowboarding/goggles)
 [x] After logging in, the user can add/update/delete items
 [] The app provides a json endpoint (catalog.json)

Rubric:
 [] implement json endpoint with all required content. U: implement additional api endpoints (rss, atom, xml)
 [] page reads category and item info from db. U: add image that reads from db
 [] Add new items. U: new item form includes image input
 [] Page includes edit/update functionality. U: Include item images.
 [] Delete functionality. U: Uses nonces to avoid cross-site request forgeries (CSRF)
 [] Implement a third party authorization and authentication process. CRUD operations should consider authorization status prior to execution.
 [] code quality is neatly formatted
 [] comments
 [] readme doc
