# pbd2json-py

TJS/ns0（.pbd）解码 / 编码器

用法：
  python tjs_ns0_decode.py in.pbd out.json              # 解码为 JSON
  python tjs_ns0_decode.py in.pbd out.tjs --tjs         # 解码为 TJS 字面量
  python tjs_ns0_decode.py in.pbd out.pbd -e in.json    # 从 JSON 编码生成 .pbd

请注意：
  本程序仅在 Python 3.15.2 上测试过。
  本程序仅测试过编解码来自 《天使☆騒々 RE-BOOT！》v1.11 的 pbd 文件。
  我个人使用尚未遇到编解码错误。



Kirikiri 的 “TJS NS0” 二进制编码脚本格式：
  文件头：魔数 "TJS/" | 变体标识 "ns0\0" | 种子值（32 位小端无符号整数）| 加密标记（16 位无符号整数）| 向量长度（16 位无符号整数）
  主体：带类型字节标记的变体数据流；16 位标记 = (校验字节 << 8) | 类型字节
            类型 0x00 = 空值（void）
            类型 0x02 = 字符串：32 位长度 + UTF‑16LE（长度按 UTF‑16 码元计数）
            类型 0x04 = 整数：64 位小端有符号整数
            类型 0x05 = 双精度浮点数：64 位小端浮点数
            类型 0x81 = 数组：32 位元素数量 + 各个元素
            类型 0xC1 = 字典：32 位键值对数量 +（字符串键 + 值）依次排列
  尾部：32 位校验和，由同一个滚动字节校验算法算出

校验字节是由种子值推导而来的滚动混淆字节。

对于README文件排版难看的问题，请原谅。
