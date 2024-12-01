<h2>Docker image</h2>

`docker pull londord/jwtgo ` </p>
`docker run -p 3000:3000 londord/jwtgo `


<h2>Postman</h2>
{"info":{"_postman_id":"e6f5e777-15fe-4bbf-8305-fe49941553e3","name":"jwtGo","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json","_exporter_id":"39194351"},"item":[{"name":"signup","request":{"method":"POST","header":[],"body":{"mode":"raw","raw":"{\r\n    \"email\": \"test@mail.ru\",\r\n    \"password\": \"testpass\"\r\n}","options":{"raw":{"language":"json"}}},"url":{"raw":"{{baseUrl}}/signup","host":["{{baseUrl}}"],"path":["signup"]}},"response":[]},{"name":"getpair","request":{"method":"GET","header":[],"url":{"raw":"{{baseUrl}}/getpair?id=89429f55-140f-4d74-8db9-c192be447d05","host":["{{baseUrl}}"],"path":["getpair"],"query":[{"key":"id","value":"89429f55-140f-4d74-8db9-c192be447d05"}]}},"response":[]},{"name":"refresh","request":{"method":"POST","header":[{"key":"Authorization","value":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzI5NzIyOTgsImlwIjoiOjoxIiwic3ViIjoiODk0MjlmNTUtMTQwZi00ZDc0LThkYjktYzE5MmJlNDQ3ZDA1In0.v5RzWtMVUWbvr_gIzALtySugEQE9hw3o_O9hPcCwlxy5OxyAkzqwTycuD7jg2lpayX1xGqEHRIZL9XAcc5_e9A","type":"text"},{"key":"X-Forwarded-For","value":"192.168.0.11","type":"text"}],"url":{"raw":"{{baseUrl}}/refresh","host":["{{baseUrl}}"],"path":["refresh"]}},"response":[]}],"event":[{"listen":"prerequest","script":{"type":"text/javascript","packages":{},"exec":[""]}},{"listen":"test","script":{"type":"text/javascript","packages":{},"exec":[""]}}],"variable":[{"key":"baseUrl","value":"http://localhost:3000","type":"string"}]}

</p></p>
<h2>Примечание</h2>

Refresh токен должен быть защищен от изменения на стороне клиента и попыток повторного использования.
  - Хранение на стороне сервера bcrypt хэша, а на стороне клиента оригинала refresh-токена обеспечивает защиту от изменения на стороне клиента.
  - Так же усложняет изменения refresh-токена на стороне клиента его хранение в куках с атрибутами HttpOnly и Secure.
  - попытки повторного использования пресекаются ротацией (при использовании refresh-токена он обновляется)
  - Замечание: этот подход не поддерживает сессии для множества устройств
