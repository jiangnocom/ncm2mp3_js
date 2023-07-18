const fs = require('fs');
// rc4秘钥
let core_before = Buffer.from([0x68, 0x7A, 0x48, 0x52, 0x41, 0x6D, 0x73, 0x6F, 0x35, 0x6B, 0x49, 0x6E, 0x62, 0x61, 0x78, 0x57])
// musicinfo秘钥
let music_info_key = Buffer.from([0x23, 0x31, 0x34, 0x6C, 0x6A, 0x6B, 0x5F, 0x21, 0x5C, 0x5D, 0x26, 0x30, 0x55, 0x3C, 0x27, 0x28])
const crypto = require('crypto')

fs.readFile('./test.ncm', (err, data) => {


    // 解码rc4key
    let core_or = 0x64//异或运算需要
    let key_length = data.slice(10, 14).readInt32LE();//1.小端排序 读出keylength
    let key_last_frame = 14 + key_length
    let key_data = data.slice(14, key_last_frame);//2.根据keylength读出keydata
    let key_data_or = []//用于存储key_data异或后数据
    key_data.map((element) => {
        key_data_or.push(element ^ core_or);//3.一个一个字节进行异或运算
    })
    let key_final_data = Buffer.from(key_data_or)//4.将keydata转为buffer
    // 5.根据秘钥解码keydata
    const key_decipher = crypto.createDecipheriv('aes-128-ecb', core_before, '');
    let key_decrypted = key_decipher.update(key_final_data, 'hex', 'utf8');
    key_decrypted += key_decipher.final('utf8');
    // console.log(key_decrypted);//去除最前面’neteasecloudmusic’17个字节，得到RC4密钥。
    let rc4_key = key_decrypted.slice(17, key_decrypted.length);
    let rc4_buffer = Buffer.from(rc4_key);



    // 解码musicmetadata
    let meta_or = 0x63;
    let music_info_length = data.slice(key_last_frame, key_last_frame + 4).readInt32LE();//1.小端排序 读出meta info length
    let mil_last_frame = key_last_frame + 4;
    let music_info = data.slice(mil_last_frame, mil_last_frame + music_info_length);
    let music_info_or = [];//2.用于存储music——info异或后数据
    music_info.map((element, index) => {
        if (index > 21) {
            music_info_or.push(element ^ meta_or);//3.一个一个字节进行异或运算
        }
    })
    let music_info_or_buffer = Buffer.from(music_info_or)
    let mif_af_string = music_info_or_buffer.toString(); //将metainfo转化为string为base64解码做准备
    let mif_af_base64de = Buffer.from(mif_af_string, 'base64');//base64解码
    const mif_decipher = crypto.createDecipheriv('aes-128-ecb', music_info_key, '');//aes解码
    let mif_decrypted = mif_decipher.update(mif_af_base64de, 'hex', 'utf8');
    mif_decrypted += mif_decipher.final('utf8');
    // console.log(mif_decrypted);
    let music_info_lsframe = mil_last_frame + music_info_length;
    // 跳过9个字节gap
    let gap_length = 9;


    // 解析图片
    let image_start_frame = music_info_lsframe + gap_length
    let image_size_buffer = data.slice(image_start_frame, image_start_frame + 4)
    let image_size = image_size_buffer.readInt32LE();//这也是小端排序 指图片数据的长度
    let image_data = data.slice(image_start_frame + 4, image_start_frame + 4 + image_size)
    fs.writeFile('./test.png', image_data, (err) => {
        if (err) {
            console.log(err);
        }
    })
    let image_data_lsframe = image_start_frame + 4 + image_size;

    // 生成s盒为了与音乐数据进行异或运算来解码
    // 1.对s表进行线性填充
    let s = [];
    for (let i = 0; i < 256; i++) {
        s[i] = i
    }
    console.log(s);
    // 2.对k表进行种子秘钥填充 若秘钥长度小于256则重复填充直至填满256
    let k = [];
    let key_times = 0;
    for (let i = 0; i < 256; i++) {
        key_times++;
        if (i % rc4_key.length == 0) {
            key_times = 0
        }
        k[i] = rc4_buffer[key_times].toString(10)

    }
    // 3.用k表对s表进行置换
    let af_val = 0;
    for (let i = 0; i < 256; i++) {
        af_val = (i + s[i] + k[i]) % 256;
        let temp = s[i];
        s[i] = s[af_val]
        s[af_val] = temp
    }
    console.log(s);
})
