# Using Google OAuth2

Task tells that need to make the service which uses Google OAuth2 and provide the name of signed google user.

## Run

I'll provide the steps to reach the result of working service.

### Requirements

- rust (can be setuped with rustup)

### Google OAuth2 setup

Need to visit (Google OAuth2 Service)[https://console.cloud.google.com/auth/clients] under your google account and create the client for your appliation. The main things that you need to get from this service: `Client ID` and `Client secret`.

> [!WARNING]
> DON'T SHARE YOUR `Client ID` AND `Client secret` TO ANYONE. OTHERWISE REWOKE THEM. I WARNED YOU :)

For convenience you can put them into `.env` file, because it ignores by git.

```env-file
export CLIENT_ID={your client id}
export CLIENT_SECRET={your client secret}
```

And you can use it as environment variable by sourcing in shell:

```bash
source .env
```

### Run service

Run application.

```bash
cargo run
```

If you want to have detailed logs, you can set the log level using `RUST_LOG` environment variable.

> [!NOTE]
> Make sure that you have corresponding CLIENT_ID and CLIENT_SECRET environment variables before start, otherwise the server won't start because of this.

## Usage

You need to open browser and go to `localhost:8000/home`. It will immediately bring you to google authentication, after which you'll be returned to `localhost:8000/home` with displaying your name. At fail will be ussed the correspongding endpoint and the error message will be displayed.

To logout visit `localhost:8000/oauth/logout`.

> [!NOTE]
> There is no mechanism of using refresh token to reset live time of access token. So in this case you need to logout and login.

## Notes

The Google OAuth2 interaction in this application was build manually. It's intentional way due learning purposes. You don't need to do the same way as I did and use a proper oauth2 library to have more secure and agile authorization.
