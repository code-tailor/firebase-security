# firebase-security
Spring-boot library to integrate security using Firebase. It additionally provides Basic authentication using pre-shared password between internal micro-services.

## Introduction
These project provide firebase security using `X-Firebase-Auth` request header. It is validate given request header with firebase using `FirebaseAuth.verifyIdTokenAsync(idToken)`, and retrieve user information into `com.google.firebase.auth.FirebaseToken`. These project set SecurityContext like `FirebaseToken` as principal, `idToken` as credentials and `empty list` as authorities.

Basic authentication provide using custom `UserDetailService`. It is only validate pre-share password. but userId or userName it is anything. It is set user authorities which is configurable from `client.service.role` and it is not specified then default is `TRUSTED_SERVICE`.

## Integration steps

### 1. Add 'firebase-admin` as dependency in pom.xml

```
<dependency>
  <groupId>com.google.firebase</groupId>
  <artifactId>firebase-admin</artifactId>
</dependency>
```

> **Notes:** The default version used is `5.5.0`.

##### Optional: Override `firebase-admin` version

- Define newer version using `firebase-admin.version` properties in pom.xml

```
<properties>
  <firebase-admin.version>5.5.0</firebase-admin.version>
</properties>
```

### 2. Initialize Firebase
- Firebase initialize in your project.
- Click [here][1] to know how to Initialize firebase

```
@Bean
  public FirebaseApp firebaseApp() {
    FileInputStream serviceAccount = new FileInputStream("path/to/serviceAccountKey.json");
    FirebaseOptions options = new FirebaseOptions.Builder()
      .setCredentials(GoogleCredentials.fromStream(serviceAccount))
      .setDatabaseUrl("https://<DATABASE_NAME>.firebaseio.com/")
      .build();
    return FirebaseApp.initializeApp(options);
  }
```

#### 3. Configure properties for basic authentication

##### Added pre-shared password

```
client.service.preSharePassword=myService
```

##### Optional: Add role for services

```
client.service.role=TEST_SERVICE
```

> **Notes:** It defaults to `TRUSTED_SERVICE`.


[1]: https://firebase.google.com/docs/admin/setup