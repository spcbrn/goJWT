Endpoints:				Handler:				HTTP:
/signup					signup					POST
/login					login					POST
/protected				protectedEndpoint		GET

Functions:
`signup` handler
`login` handler
`GenerateToken`
`TokenVerifyMiddleware`


JWT Structure:
{Base64 encoded Header}.{Base64 encoded Payload}.{Signature}
e309asoijasJfpqoij4e3p-90823u.asodfieow4hjolsKDFJLKJHFOihsaf89asdlh.asdfkl;jfSAsoaihoigelhasd

Header (JSON):
- Algorithm and Token Type
- { "alg": "HS256", "typ": "JWT" } <-before encoding

Payload (JSON):
- User and additional data such as token expiry etc...
- Three types of claims: Registered, Public and Private
- { "email": "whatever@hi.com", "Issure": "course" } <-before encoding

Signature (String computed from Header, Payload and a secret):
- An algorithm to generate the Signature
- Digitally signed using a secret string only known to developer

JWT resources:
- https://jwt.io
- https://tools.ietf.org/html/rfc7519

DB:
URI - postgres://hbqbvsuvzkiwyv:96d4d273802750abef0437f1bfe640787b5a514afec668bd32bb0536834ad5f4@ec2-23-21-76-49.compute-1.amazonaws.com:5432/d8fn2og7m2c9ag
user - hbqbvsuvzkiwyv
password - 96d4d273802750abef0437f1bfe640787b5a514afec668bd32bb0536834ad5f4