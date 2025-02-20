import 'package:api/db_manager.dart';
import 'package:api/encrypt_password.dart';
import 'package:api/models/users.dart';

class UsersRepository {
  static DbManager dbManager = DbManager.collection("users");
  static Future<dynamic> insertOne(User user) async {
    String encriptedPassword = encryptPassword(user.password);
    user.password = encriptedPassword;
    final result = await dbManager.insertOne(user.toJsonInsert());
    return result;
  }

  static Future<dynamic> findAll() async {
    final result = await dbManager.findAll();
    return result;
  }

  static Future<dynamic> findOne(Map<String, dynamic> filter) async {
    final result = await dbManager.findOne(filter);
    return result;
  }

  static Future<bool> deleteOne(Map<String, dynamic> filter) async {
    try {
      final result = await dbManager.deleteOne(filter);
      return result; // Suponiendo que dbManager.deleteOne devuelve true/false
    } catch (e) {
      print("Error al eliminar usuario: $e");
      return false;
    }
  }

  static Future<bool> updateOne(
    Map<String, dynamic> filter,
    Map<String, dynamic> updateData,
  ) async {
    return await dbManager.updateOne(filter, updateData);
  }
}
