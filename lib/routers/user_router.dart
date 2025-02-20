import 'dart:convert';
import 'package:shelf/shelf.dart';
import 'package:shelf_router/shelf_router.dart';
import 'package:api/models/users.dart';
import 'package:api/repositories/user_repository.dart';
import 'package:api/encrypt_password.dart' as encrypter;
import 'package:api/user_token_service.dart' as jwt_service;
import 'package:mongo_dart/mongo_dart.dart';

final userRouter =
    Router()
      ..get('/users', _usersHandler)
      ..post('/users/signUp', _signUpHanler)
      ..post('/users/login', _loginHanler)
      ..get('/users/<id>', _getUserHanler)
      ..delete('/users/<id>', _deleteUserHandler);

Future<Response> _loginHanler(Request request) async {
  final credentialRequestBody = await request.readAsString();
  final Map<String, dynamic> bodyParams = json.decode(credentialRequestBody);
  // Vericamos que las credenciales vengan el body de la petición
  final String email =
      bodyParams.containsKey('email') ? bodyParams['email'] : '';
  final String password =
      bodyParams.containsKey('password') ? bodyParams['password'] : '';
  // Creamos las credenciales con la contraseña cifrada porque en la base de
  final Map<String, dynamic> credentials = {
    "email": email,
    "password": password,
  };
  final autorizedUser = await areCredencialValid(credentials);
  if (!autorizedUser) {
    return Response.unauthorized(
      json.encode({
        "message": "Usuario autorizado o las credenciales son inválida",
        "authenticated": false,
      }),
    );
  } else {
    String token = jwt_service.UserTokenService.generateJwt({"email": email});
    return Response.ok(
      json.encode({
        "message": "Usuario autorizado",
        "authenticated": true,
        "token": token,
      }),
    );
  }
}

Future<bool> areCredencialValid(Map<String, dynamic> credentials) async {
  final user = await UsersRepository.findOne({"email": credentials["email"]});
  if (user != null) {
    final encryptedPass = encrypter.checkPassword(
      credentials["password"],
      user["password"],
    );
    return encryptedPass;
  } else {
    return false;
  }
}

Future<Response> _usersHandler(Request request) async {
  final dynamic token =
      request.headers.containsKey("token") ? request.headers["token"] : "";
  final Map<String, dynamic> verifiedToken = jwt_service
      .UserTokenService.verifyJwt(token);
  if (verifiedToken['authorized'] == false) {
    return Response.unauthorized(json.encode(verifiedToken));
  } else {
    final users = await UsersRepository.findAll();
    return Response.ok(json.encode(users));
  }
}

Future<Response> _signUpHanler(Request request) async {
  final userRequestBody = await request.readAsString();
  final user = User.fromJson(json.decode(userRequestBody));
  final List<Map<String, String>> userValidateErrors = await validateUser(user);
  dynamic userCreated;
  if (userValidateErrors.isEmpty) {
    userCreated = await UsersRepository.insertOne(user);
    // if hubo un error al insertar el registro
    if (userCreated.containsKey("error")) userValidateErrors.add(userCreated);
  }
  if (userValidateErrors.isNotEmpty) {
    final encodedError = jsonEncode(userValidateErrors);
    return Response.badRequest(
      body: encodedError,
      headers: {'content-type': 'application/json'},
    );
  } else {
    return Response.ok('Usuario creado correctamente $userCreated');
  }
}

validateUser(User user) async {
  List<Map<String, String>> errors = [];
  final userFound = await UsersRepository.findOne({"email": user.email});

  if (userFound != null) {
    errors.add({"email": "The user already exists with the same email"});
  }

  if (user.email.isEmpty) {
    errors.add({"name": "Name is a required field"});
  }

  if (user.surname.isEmpty) {
    errors.add({"surname": "surname is a required field"});
  }

  if (user.password.isEmpty || user.password.length < 6) {
    errors.add({"surname": "Password should have at least 6 characters"});
  }

  return errors;
}

Future<Response> _getUserHanler(Request request) async {
  final dynamic token =
      request.headers.containsKey("token") ? request.headers["token"] : "";
  final Map<String, dynamic> verifiedToken = jwt_service
      .UserTokenService.verifyJwt(token);
  if (verifiedToken['authorized'] == false) {
    return Response.unauthorized(json.encode(verifiedToken));
  } else {
    dynamic userId = ObjectId.fromHexString(request.params['id'].toString());
    final users = await UsersRepository.findOne({"_id": userId});
    return Response.ok(json.encode(users));
  }
}

Future<Response> _deleteUserHandler(Request request) async {
  // Obtener el token del header
  final String token = request.headers["token"] ?? "";

  // Verificar el token
  final Map<String, dynamic> verifiedToken = jwt_service
      .UserTokenService.verifyJwt(token);
  if (verifiedToken['authorized'] == false) {
    return Response.unauthorized(
      json.encode({"message": "Acceso no autorizado", "authorized": false}),
    );
  }

  // Obtener el ID del usuario desde la URL
  final String userId = request.params['id'] ?? "";
  if (userId.isEmpty) {
    return Response.badRequest(
      body: json.encode({"error": "ID de usuario no proporcionado"}),
    );
  }

  try {
    // Convertir el ID a ObjectId
    final ObjectId objectId = ObjectId.fromHexString(userId);

    // Buscar si el usuario existe
    final user = await UsersRepository.findOne({"_id": objectId});
    if (user == null) {
      return Response.notFound(json.encode({"error": "Usuario no encontrado"}));
    }

    // Eliminar usuario
    final result = await UsersRepository.deleteOne({"_id": objectId});
    if (result) {
      return Response.ok(
        json.encode({"message": "Usuario eliminado correctamente"}),
      );
    } else {
      return Response.internalServerError(
        body: json.encode({"error": "Error al eliminar el usuario"}),
      );
    }
  } catch (e) {
    return Response.internalServerError(
      body: json.encode({"error": "ID no válido o error en el servidor"}),
    );
  }
}
