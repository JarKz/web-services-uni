# Main information

The task describes that there's must be a microservice containing 3 services at least. And it must be deployed by docker + minikube (k8s).

There's 3 services:

- user service (for registration, signing, JWT and refresh tokens)
- library service (for managing books)
- deployment service (for managing book borrows)

| Service name       | URL (with port)           |
| :----------------- | :------------------------ |
| user service       | http://192.168.49.2:30080 |
| library service    | http://192.168.49.2:30081 |
| deployment service | http://192.168.49.2:30082 |

## user service

| Endpoint                      | HTTP Method | Requirements                              | Description                                                                                                                  |
| :---------------------------- | :---------- | :---------------------------------------- | :--------------------------------------------------------------------------------------------------------------------------- |
| /api/sign-up                  | POST        | 'Content-Type: application/json'          | Made for registering user, accepts JSON data with fields: 'username', 'password' and 'email'.                                |
| /api/sign-in                  | POST        | 'Content-Type: application/json'          | Made for signing indo system. Accepts JSON data with fields: 'username' and 'password'. Returns JWT and refresh token.       |
| /api/refresh                  | POST        | 'Content-Type: application/json'          | Made for refreshing JWT by refresh-token. Accepts JSON data with fields: 'refresh_token'. Returns new JWT and refresh token. |
| /service-api/verify-user/{id} | GET         | 'Authorization: ApiKey {service_api_key}' | Made for verifying a user by user_id. Rely on HTTP error code. The 200 OK code equal to valid user, otherwise — invalid      |

## library service

| Endpoint                      | HTTP Method | Requirements                                                                                                  | Description                                                                                                              |
| :---------------------------- | :---------- | :------------------------------------------------------------------------------------------------------------ | :----------------------------------------------------------------------------------------------------------------------- |
| /api/books                    | GET         | 'Authorization: Bearer {JWT}'                                                                                 | Retrieves all books from library.                                                                                        |
| /api/books/{id}               | GET         | 'Authorization: Bearer {JWT}'                                                                                 | Retrieves specific book. Can return 404 if not found.                                                                    |
| /api/books/{id}               | DELETE      | 'Authorization: Bearer {JWT}' && `(role == Admin \|\| role == Librarian)`                                     | Deletes the specific book.                                                                                               |
| /api/books                    | POST        | 'Authorization: Bearer {JWT}' && 'Content-Type: application/json' && `(role == Admin \|\| role == Librarian)` | Creates a new book, if the same title and author together doesn't exists.                                                |
| /service-api/verify-book/{id} | GET         | 'Authorization: ApiKey {service_api_key}'                                                                     | Made for verifying a book by book_id. Rely on HTTP error code. The 200 OK code equal to valid book, otherwise — invalid. |

## borrowing service

| Endpoint              | HTTP Method | Requirements                                                                                                  | Description                                                                                                                                                   |
| :-------------------- | :---------- | :------------------------------------------------------------------------------------------------------------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| /api/borrow-book      | POST        | 'Authorization: Bearer {JWT}' && 'Content-Type: application/json' && `(role == Admin \|\| role == Librarian)` | Accepts JSON data with fields: 'user_id', 'book_id' and 'expected_return_at'. The 'user_id' and 'book_id' must be valid. Cannot borrow already borrowed book. |
| /api/return-book      | POST        | 'Authorization: Bearer {JWT}' && 'Content-Type: application/json' && `(role == Admin \|\| role == Librarian)` | Accepts JSON data with fields: 'user_id', 'book_id'. The 'user_id' and 'book_id' must be valid. Cannot return the book under another user_id.                 |
| /api/unreturned-books | POST        | 'Authorization: Bearer {JWT}' && 'Conten-Type: application/json'                                              | Accepts JSON data with fields: 'user_id'. Returns the list of unreturned books.                                                                               |

## Usage

First, make sure that you have installed minikube and docker (not rootless! minikube doesn't work with this type of docker).

Start minikube cluster and enter into its environment:

```bash
minikube start
eval $(minikube docker-env)
```

Then build 3 images:

```bash
docker build -t user_service:latest user_service/
docker build -t library_service:latest library_service/
docker build -t borrowing_service:latest borrowing_service/
```

> [!NOTE]
> You can build them together in separated tabs/panes of terminal. It will make less time to build images.

And run a script which setups the k8s deployment and services:

```bash
./setup-k8s.sh
```

Mapped URLs and ports:

| Service name      | URL                 | Port  |
| :---------------- | :------------------ | :---- |
| User service      | http://192.168.49.2 | 30080 |
| Library service   | http://192.168.49.2 | 30081 |
| Borrowing service | http://192.168.49.2 | 30082 |

> [!WARNING]
> The URL you have from minikube may be different. You can check it by `minikube service {service-name} --url` (e.g. `minikube service user-service --url`).

## Shut downing

Firstly, stop the minikube:

```bash
minikube stop
```

Then delete the minikube:

```bash
minikube delete
```

Why? Because it will free a lot of space that minikube had allocate. I'd the worst experience when minikube ate ALL MY DISK SPACE. Please, be careful and monitor it.

## Additional Note

The application was made in educational purposes and it will be insecure. At least, there's no TLS. But, you can adjust security except TLS, there's:

1. Each service have the `.env` file which contains some important environments that k8s loads into configmap. There's the `SERVICE_API_KEY` variable that allows services to detect the HTTP request from another service. There's just a simple string, but you can change it (all of the must be same!).
2. There's `private.pem` and `public.pem` files for RS256 signing and verifying JWT tokens. Instead of using shared sercet (the HS256 algorithm), I use public keys to verify signatures. You can re-generate these files by `openssl`. Be sure that all services have the same `public.pem` keys.
