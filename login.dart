/*
四川大学统一登录认证脚本——dart
使用方法：
  1.创建LoginInstance类
  2.调用LoginInstance类方法getCapcode，返回Uint8List字节数组，可显示出来
  3.调用LoginInstance类方法get_access_token获取token和refresh_token
 */

import 'dart:convert';
import 'dart:typed_data';
import 'package:dart_sm/dart_sm.dart';
import 'package:dio/dio.dart';

String bytesToHex(Uint8List bytes) {
  var result = StringBuffer();
  for (var byte in bytes) {
    var part = byte.toRadixString(16);
    part = part.padLeft(2, '0');
    result.write(part);
  }
  return result.toString();
}

String hexToBase64(String hexStr) {
  if (hexStr.length % 2 != 0) {
    throw const FormatException('Invalid hexadecimal string');
  }
  Uint8List bytes = Uint8List(hexStr.length ~/ 2);
  for (var i = 0; i < hexStr.length; i += 2) {
    var hexByte = hexStr.substring(i, i + 2);
    bytes[i ~/ 2] = int.parse(hexByte, radix: 16);
  }
  return base64Encode(bytes);
}

String sm2_base64_encrypt(String content,String publicKey){
  var keybytes = base64Decode(publicKey);
  String cipherText = SM2.encrypt(content,bytesToHex(keybytes),cipherMode: C1C2C3);
  String encrypted_text = hexToBase64("04$cipherText");
  return encrypted_text;
}

class LoginInstance{
  late String capcode;
  final Dio dio = Dio();
  Future<Uint8List> getCapcode() async {
    final timestamp = (DateTime.now().millisecondsSinceEpoch).toString();
    final response = await dio.get(
      "https://id.scu.edu.cn/api/public/bff/v1.2/one_time_login/captcha?_enterprise_id=scdx&timestamp=$timestamp",
    );
    final result = response.data;
    capcode = result['data']['code'];
    final captcha = result['data']['captcha'];
    return base64Decode(captcha);
  }

  Future<Map<String, String>> get_access_token(String client_id, String username, String password,String captext) async {
    final sm2Response = await dio.post("https://id.scu.edu.cn/api/public/bff/v1.2/sm2_key", data: {});
    final sm2Result = sm2Response.data;
    print(sm2Result);
    final sm2Pubkey = sm2Result['data']['publicKey'];
    final codeSm2 = sm2Result['data']['code'];
    final passwordEncrypt = sm2_base64_encrypt(password, sm2Pubkey);
    final payload = jsonEncode({
      "client_id": client_id,
      "grant_type": "password",
      "scope": "read",
      "username": username,
      "password": passwordEncrypt,
      "_enterprise_id": "scdx",
      "sm2_code": codeSm2,
      "cap_code": capcode,
      "cap_text": captext,
    });

    final headers = {
      'Accept': 'application/json, text/plain, */*',
      'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Content-Type': 'application/json;charset=UTF-8',
      'Origin': 'https://id.scu.edu.cn',
      'Pragma': 'no-cache',
      'Referer': 'https://id.scu.edu.cn/frontend/login',
      'Sec-Fetch-Dest': 'empty',
      'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Site': 'same-origin',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
      'sec-ch-ua': '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"',
    };

    final tokenResponse = await dio.post(
      "https://id.scu.edu.cn/api/public/bff/v1.2/rest_token",
      options: Options(headers: headers),
      data: payload,
    );

    final tokenResult = tokenResponse.data;
    if (!tokenResult['success']) {
      throw tokenResponse.data;
    }
    final accessToken = tokenResult['data']['access_token'];
    final refreshToken = tokenResult['data']['refresh_token'];
    return {'access_token': accessToken, 'refresh_token': refreshToken};
  }
}
