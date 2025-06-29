# SOAP Book library service

Task tells that need to make the 'library' for catalogization books and use for it SOAP.

## Run

To run this application need to use SeaORM migrations for database setup. This can be done with `sea-orm-cli` application.

```bash
sea-orm-cli migrate up -u "sqlite://books.db?mode=rwc"
```

This will create new `books.db` file if it doesn't exists and fill it with tables by migration schema. Make sure that you use the last migration.
And now you can run server.

```bash
cargo run
```

## Scripts

The application interact using XML and for ease to write scripts I provide here a templates for curl.

Get book by isbn:

```bash
curl -X POST localhost:8000/library-service -H "Content-Type: application/xml" -d '
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:lib="http://example.org/library-service">
  <soapenv:Body>
    <lib:Request>
      <lib:GetBook>
        <lib:isbn>123</lib:isbn>
      </lib:GetBook>
    </lib:Request>
  </soapenv:Body>
</soapenv:Envelope>
'
```

Add book:

```bash
curl -X POST localhost:8000/library-service -H "Content-Type: application/xml" -d '
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:lib="http://example.org/library-service">
  <soapenv:Body>
    <lib:Request>
      <lib:AddBook>
        <lib:Book>
          <lib:isbn>123</lib:isbn>
          <lib:title>Master and Margaret</lib:title>
          <lib:author>Mikhail Bulgakov</lib:author>
          <lib:publisher>Moscow AST</lib:publisher>
          <lib:publicationYear>2005</lib:publicationYear>
          <lib:language>Russian</lib:language>
        </lib:Book>
      </lib:AddBook>
    </lib:Request>
  </soapenv:Body>
</soapenv:Envelope>
'
```

Delete book by isbn:

```bash
curl -X POST localhost:8000/library-service -H "Content-Type: application/xml" -d '
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:lib="http://example.org/library-service">
  <soapenv:Body>
    <lib:Request>
      <lib:DeleteBook>
        <lib:isbn>123</lib:isbn>
      </lib:DeleteBook>
    </lib:Request>
  </soapenv:Body>
</soapenv:Envelope>
'
```
