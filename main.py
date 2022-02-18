#pip install pycryptodome
#pip install pytelegrambotapi
#pip install random2

import binascii
from config import bot_token
from typing import Tuple, Union
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import logging
from telegram.ext import Updater, CommandHandler, ConversationHandler, MessageHandler, Filters, CallbackContext
from telegram import ReplyKeyboardMarkup, ReplyKeyboardRemove, Update

#bot_token = 'token'


def to_bytes(string: str) -> bytes:
    _bytes = string.encode(encoding='utf-8')
    return _bytes


def from_bytes(b_string: bytes) -> str:
    _str = b_string.decode()
    return _str


def generate_key(password: str) -> bytes:
    _pass = to_bytes(password)
    hash_key = SHA256.new()
    hash_key.update(_pass)
    secret_key = hash_key.digest()
    return secret_key


def encrypt_aes_gcm(
        msg: str, password: str
) -> Tuple[bytes, Union[bytes, bytearray, memoryview], bytes]:
    secret_key = generate_key(password)
    aesCipher = AES.new(secret_key, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(to_bytes(msg))
    return ciphertext, aesCipher.nonce, authTag


def decrypt_aes_gcm(encryptedMsg: str, password: str) -> str:
    (ciphertext, nonce, authTag) = encryptedMsg
    secret_key = generate_key(password)
    aesCipher = AES.new(secret_key, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return from_bytes(plaintext)


logger = logging.getLogger(__name__)

CHOOSING, MSG_TAG, TYPING_MSG, TYPING_PASS, PWD_STATE = range(5)

reply_keyboard = [['зашифровать', 'расшифровать']]
choosing_keyboard = [['удалить', 'сохранить']]

markup = ReplyKeyboardMarkup(reply_keyboard,
                             one_time_keyboard=True,
                             resize_keyboard=True)
choosing_markup = ReplyKeyboardMarkup(choosing_keyboard,
                                      one_time_keyboard=True,
                                      resize_keyboard=True)


def start(update: Update, context: CallbackContext) -> int:
    msg_id = update.message.message_id
    context.user_data.setdefault('trash_ids', []).append(msg_id)
    bot_msg_id = update.message.reply_text(
        f"Привет, я могу зашифровать твои заметки, чтобы они были в безопасности ヽ(´▽`)/\n"
        f"Можешь написать /restart, чтобы перезапустить диалог")
    context.user_data['trash_ids'].append(bot_msg_id.message_id)
    bot_msg_id_ = update.message.reply_text(
        f"В конце я очищу диалог, "
        f"таким образом все будет безопасно (-`Ღ´-)\n",
        reply_markup=markup,
    )
    context.user_data['trash_ids'].append(bot_msg_id_.message_id)
    return CHOOSING


def first_choice(update: Update, context: CallbackContext) -> int:
    msg_id = update.message.message_id
    context.user_data['trash_ids'].append(msg_id)
    text = update.message.text
    context.user_data['choice'] = text
    bot_msg_id = update.message.reply_text(
        f"Давай выберем имя для твоей заметки. Просто отправь мне его \n\nฅ^-ﻌ-^ฅ",
        reply_markup=ReplyKeyboardRemove())
    context.user_data['trash_ids'].append(bot_msg_id.message_id)
    return MSG_TAG


def msg_tag(update: Update, context: CallbackContext) -> int:
    msg_id = update.message.message_id
    context.user_data['trash_ids'].append(msg_id)
    text = update.message.text
    context.user_data['tag'] = text
    bot_msg_id = update.message.reply_text(
        f"Теперь пришлите мне текст, чтобы {context.user_data['choice'].split()[0]}: его"
    )
    context.user_data['trash_ids'].append(bot_msg_id.message_id)
    return TYPING_MSG


#tag


def received_msg(update: Update, context: CallbackContext) -> int:
    msg_id = update.message.message_id
    context.user_data['trash_ids'].append(msg_id)
    text = update.message.text
    context.user_data['message'] = text
    bot_msg_id = update.message.reply_text(
        f"Пришли пароль, чтобы {context.user_data['choice'].split()[0]} твою заметку \n\n(`･ω･´)\n"
    )
    context.user_data['trash_ids'].append(bot_msg_id.message_id)
    return TYPING_PASS


def received_pass(update: Update, context: CallbackContext) -> int:
    msg_id = update.message.message_id
    context.user_data['trash_ids'].append(msg_id)
    text = update.message.text
    context.user_data['password'] = text
    context.user_data['pwd_msg_id'] = msg_id
    bot_msg_id = update.message.reply_text(
        f"Хотите, чтобы я сохранил пароль?", reply_markup=choosing_markup)
    context.user_data['trash_ids'].append(bot_msg_id.message_id)
    return PWD_STATE


def received_password_state(update: Update, context: CallbackContext):
    text = update.message.text
    msg_id = update.message.message_id
    context.user_data['trash_ids'].append(msg_id)
    if text == 'сохранить':
        context.user_data['pwd_state'] = text
    elif text == 'удалить':
        context.user_data['pwd_state'] = text
    bot_msg_id = update.message.reply_text(f"Секунду...",
                                           reply_markup=ReplyKeyboardRemove())
    context.user_data['trash_ids'].append(bot_msg_id.message_id)
    result_msg(update, context)
    return ConversationHandler.END


def result_msg(update: Update, context: CallbackContext):
    method_choice = context.user_data['choice']
    msg_to = context.user_data['message']
    pass_to = context.user_data['password']
    if method_choice == 'зашифровать':
        raw_res_msg = encrypt_aes_gcm(msg_to, pass_to)
        res_msg_list = [
            binascii.hexlify(chunk).decode('utf-8') for chunk in raw_res_msg
        ]
        res_msg = ':'.join(res_msg_list)
    elif method_choice == 'расшифровать':
        try:
            raw_encr_msg = msg_to.split(":")
            encr_msg_tuple = tuple(
                binascii.unhexlify(chunk) for chunk in raw_encr_msg)
            res_msg = decrypt_aes_gcm(encr_msg_tuple, pass_to)
            print(type(res_msg))
        except Exception as e:
            print(f"Блин, что-то пошло не так в {e.__class__}")
            return wrong_data(update, context)
            # return None  # ConversationHandler.END
    if context.user_data['pwd_state'] == 'сохранить':
        update.message.reply_text(f"tag: {context.user_data['tag']}\n"
                                  f"password: {context.user_data['password']}\nЕсли захотите сделать еще одну заметку или расшифровать старую, напишите /start")
    elif context.user_data['pwd_state'] == 'удалить':
        update.message.reply_text(f"tag: {context.user_data['tag']}\nЕсли захотите сделать еще одну заметку или расшифровать старую, напишите /start")
    update.message.reply_text(f"{res_msg}")
    for itm in context.user_data['trash_ids']:
        try:
            context.bot.delete_message(update.message.chat_id, itm)
        except Exception as e:
            print(
                f"Ужас (๑•́ ₃ •̀๑) \nчто-то пошло не так в {result_msg.__name__} , пока удалялась trash_ID. {e.__class__}"
            )
    context.user_data.clear()
    # return ConversationHandler.END


def end_conv(update: Update, context: CallbackContext) -> int:
    msg_id = update.message.message_id
    context.user_data.setdefault('trash_ids', []).append(msg_id)
    user = update.message.from_user
    logger.info("User %s canceled the conversation.", user.first_name)
    bot_msg_id = update.message.reply_text(
        'Напиши /restart, чтобы перезапустить диалог',
        reply_markup=ReplyKeyboardRemove())
    for itm in context.user_data['trash_ids']:
        try:
            context.bot.delete_message(update.message.chat_id, itm)
        except Exception as e:
            print(
                f"Ужас (๑•́ ₃ •̀๑) \nЧто-то пошло не так в {end_conv.__name__}  {e.__class__}"
            )
    context.user_data['trash_ids'].append(bot_msg_id.message_id)
    return ConversationHandler.END


def wrong_data(update: object, context: CallbackContext):
    msg_id = update.message.message_id
    context.user_data['trash_ids'].append(msg_id)
    bot_msg_id = update.message.reply_text(
        f"Ужас (๑•́ ₃ •̀๑) \nПароль или сообщение некорректны,"
        f"\nнапиши /restart",
        reply_markup=ReplyKeyboardRemove())
    context.user_data['trash_ids'].append(bot_msg_id.message_id)
    return ConversationHandler.END


def error_handler(update: object, context: CallbackContext):
    msg_id = update.message.message_id
    context.user_data.setdefault('trash_ids', []).append(msg_id)
    logger.error(
        msg="Ошибка при обработке запроса:",
        exc_info=context.error,
    )
    bot_msg_id = update.message.reply_text(
        f"Что-то пошло не так, напиши /start или /restart, чтобы перезапустить диалог",
        reply_markup=ReplyKeyboardRemove())
    context.user_data['trash_ids'].append(bot_msg_id.message_id)
    return end_conv


def main() -> None:
    updater = Updater(bot_token)

    dispatcher = updater.dispatcher

    conv_handler = ConversationHandler(
        entry_points=[CommandHandler('start', start)],
        states={
            CHOOSING: [
                MessageHandler(
                    Filters.regex('^(расшифровать|зашифровать)$')
                    & ~Filters.command, first_choice),
            ],
            MSG_TAG: [
                MessageHandler(Filters.text & ~Filters.command, msg_tag),
            ],
            TYPING_MSG: [
                MessageHandler(Filters.text & ~Filters.command, received_msg),
            ],
            TYPING_PASS: [
                MessageHandler(Filters.text & ~Filters.command, received_pass),
            ],
            PWD_STATE: [
                MessageHandler(
                    Filters.regex('^(удалить|сохранить)$') & ~Filters.command,
                    received_password_state),
            ],
        },
        fallbacks=[CommandHandler('restart', end_conv)],
    )

    dispatcher.add_handler(conv_handler)
    dispatcher.add_error_handler(error_handler)
    dispatcher.add_handler(MessageHandler(Filters.text, error_handler))
    updater.start_polling()
    updater.idle()


if __name__ == '__main__':
    main()
