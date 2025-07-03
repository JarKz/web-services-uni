# RESTful Ordering service

Task tells that need to make the service based on orders using RESTful API. The orders means orders from internet-stores.

## Run

I'll provide the steps to reach the result of working service.

### Requirements

- docker + docker-compose applications
- sea-orm-cli application
- rust (can be setuped with rustup)

### Database setup

Setup with docker-compose:

```bash
docker-compose up -d
```

> [!NOTE]
> For some of us need to use `sudo` or change the current user to root if it is need. It's only for setup.
>
> The database user and password in yaml file are example and shouldn't be used for production.

Run SeaORM migration:

```bash
sea migrate up -u "postgres://postgres:test@localhost/orders" # "postgres://{user}:{password}@{host}/{database_name}"
```

> [!NOTE]
> The entities are generated and don't neet te bo re:generated.

### Run service

Run the servive:

```bash
cargo run
```

If you want to have detailed logs, you can set the log level using `RUST_LOG` environment variable.

## Scripts

The application interacts using JSON and for ease to write scripts I provide here a templates for curl.

Get all orders:

```bash
curl localhost:8000/orders
```

Get order by id:

```bash
curl localhost:8000/orders/{id}
```

Add new order:

```bash
curl -X POST localhost:8000/orders -H 'Content-Type: application/json' -d '
{
  "customer_name": "Alexey",
  "customer_email": "example@mail.com",
  "customer_commentary": "Ring the doorbell",
  "price_total": "123.43",
  "items": [{ "name": "Toy", "quantity": 1 }],
  "shipping_address": "City, Street, House"
}'
```

Modify the order:

```bash
curl -X PATCH localhost:8000/orders/1 -H 'Content-Type: application/json' -d '
{
  "status": "shipped"
}'
```

Delete the order:

```bash
curl -X DELETE localhost:8000/orders/1
```

## Notes

The main struggle during writing service is the order definition. Usually the orders have description of items and their quantity. But the SQL databases can't store complex structure and requires the normalized data which means a lot of works with data.

For example, to add order, I need firstly insert order without items and then insert the items in specific table. To modify I need also modify the order and update, but the items should be wiped for specific order and recreated with other items. I'm glad to be in era that there is a transaction which can rollback when somewhere is broken.
