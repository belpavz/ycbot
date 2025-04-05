import logging
from dotenv import load_dotenv
from app2 import db, UserPhone
import os
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, KeyboardButton, ReplyKeyboardMarkup, constants
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes,
    CallbackQueryHandler,)

from yclients import YClientsAPI
from datetime import datetime, date
import json


# Настройка логирования
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.WARNING
)
logger = logging.getLogger(__name__)

load_dotenv()

YCLIENTS_API_TOKEN = os.getenv('YCLIENTS_API_TOKEN')
COMPANY_ID = os.getenv('COMPANY_ID')
FORM_ID = os.getenv('FORM_ID')
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')

if not all([YCLIENTS_API_TOKEN, COMPANY_ID, FORM_ID, TELEGRAM_BOT_TOKEN]):
    logger.critical(
        "Необходимо установить переменные окружения: YCLIENTS_API_TOKEN, YCLIENTS_COMPANY_ID, FORM_ID, TELEGRAM_BOT_TOKEN")
    raise ValueError("Отсутствуют необходимые переменные окружения")

# Инициализация API YCLIENTS
# api = YClientsAPI(token=YCLIENTS_API_TOKEN, company_id=COMPANY_ID, form_id=FORM_ID)
# Создаем функцию для получения API для конкретного пользователя


def get_user_api(context):
    try:
        company_id = context.user_data.get("company_id", COMPANY_ID)
        form_id = context.user_data.get("form_id", FORM_ID)

        logger.info(
            f"Инициализация API с company_id={company_id}, form_id={form_id}")
        return YClientsAPI(token=YCLIENTS_API_TOKEN, company_id=company_id, form_id=form_id)
    except Exception as e:
        logger.error(f"Ошибка при инициализации API: {e}")
        # Возвращаем API с дефолтными параметрами
        return YClientsAPI(token=YCLIENTS_API_TOKEN, company_id=COMPANY_ID, form_id=FORM_ID)


# Проверка интеграции для салона.
def is_integration_active(user_id, company_id):
    from app2 import UsersYclients, db

    # Проверяем, есть ли активная интеграция для данного салона
    salon_integration = UsersYclients.query.filter_by(
        salon_id=company_id,
        is_active=True
    ).first()

    if salon_integration:
        # Интеграция для салона активна
        return True
    else:
        # Проверяем, является ли пользователь администратором с отключенной интеграцией
        admin_entry = UsersYclients.query.filter_by(
            user_id=user_id,
            salon_id=company_id,
            is_active=False
        ).first()

        if admin_entry:
            # Это администратор с отключенной интеграцией
            return False
        else:
            # Проверяем, есть ли вообще интеграция для этого салона
            any_integration = UsersYclients.query.filter_by(
                salon_id=company_id
            ).first()

            return any_integration is not None


# Загрузка и сохранение базы данных телефонов
def get_user_phone(telegram_id):
    user_phone = UserPhone.query.filter_by(
        telegram_id=str(telegram_id)).first()
    return user_phone.phone if user_phone else None


def save_user_phone(telegram_id, phone):
    user_phone = UserPhone.query.filter_by(
        telegram_id=str(telegram_id)).first()
    if user_phone:
        user_phone.phone = phone
    else:
        user_phone = UserPhone(telegram_id=str(telegram_id), phone=phone)
        db.session.add(user_phone)
    db.session.commit()


# Получение списка сотрудников
def get_staff(context):
    api = get_user_api(context)
    try:
        staff = api.get_staff()
        if staff and staff['success']:
            return staff['data']
        else:
            logger.error(
                f"Ошибка при получении списка сотрудников: {staff.get('meta', 'No meta data available') if staff else 'No response'}")
            return None
    except Exception as e:
        logger.error(f"Исключение при получении списка сотрудников: {e}")
        return None


# Получение списка услуг
def get_services(context, staff_id=None):
    try:
        api = get_user_api(context)
        services = api.get_services(staff_id=staff_id)
        if services and services['success']:
            return services['data']['services']
        else:
            logger.error(
                f"Ошибка при получении списка услуг: {services.get('meta', 'No meta data available') if services else 'No response'}")
            return None
    except Exception as e:
        logger.error(f"Исключение при получении списка услуг: {e}")
        return None


# Получение доступных дат для записи
def get_available_days(context, service_id, staff_id=None):
    try:
        api = get_user_api(context)
        available_days = api.get_available_days(
            staff_id=staff_id, service_id=service_id)
        if available_days and available_days['success']:
            return available_days['data']['booking_dates']
        else:
            logger.info(
                f"Получение доступных дней для service_id={service_id}, staff_id={staff_id}")
            return None
    except Exception as e:
        logger.error(
            f"Исключение при получении списка доступных дат: {e}", exc_info=True)
        return None

# Получение доступного времени для записи


def get_available_times(context, service_id, staff_id, selected_date):
    try:
        api = get_user_api(context)
        available_times = api.get_available_times(
            staff_id=staff_id, service_id=service_id, day=selected_date)
        if available_times and available_times['success']:
            return available_times['data']
        else:
            logger.error(
                f"Ошибка при получении доступного времени: {available_times.get('meta', 'No meta data available') if available_times else 'No response'}")
            return None
    except Exception as e:
        logger.error(f"Исключение при получении доступного времени: {e}")
        return None


# Функция для перевода месяца на русский
def translate_month_to_russian(month_year):
    month_year_parts = month_year.split()
    month = month_year_parts[0]
    year = month_year_parts[1]
    month_dict = {
        "January": "Январь",
        "February": "Февраль",
        "March": "Март",
        "April": "Апрель",
        "May": "Май",
        "June": "Июнь",
        "July": "Июль",
        "August": "Август",
        "September": "Сентябрь",
        "October": "Октябрь",
        "November": "Ноябрь",
        "December": "Декабрь",
    }
    translated_month = month_dict.get(month)
    return f"{translated_month} {year}" if translated_month else month_year


# Функция для получения дня недели на русском
def get_weekday_russian(date_obj):
    weekday_dict = {
        0: "Пн",
        1: "Вт",
        2: "Ср",
        3: "Чт",
        4: "Пт",
        5: "Сб",
        6: "Вс"
    }
    return weekday_dict[date_obj.weekday()]


# Команда /start
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    start_param = context.args[0] if context.args else None

    if start_param:
        try:
            # Проверяем формат параметра
            if '-' not in start_param:
                raise ValueError("Неверный формат параметра")

            company_id, form_id = start_param.split('-')

            # Проверяем, что параметры не пустые
            if not company_id or not form_id:
                raise ValueError("Пустые параметры")

            # Сохраняем параметры в данных пользователя
            context.user_data["company_id"] = company_id
            context.user_data["form_id"] = form_id

            await update.message.reply_text(
                f"Привет! Я бот для онлайн-записи в компанию {company_id}. "
                f"Используйте /book, чтобы записаться на услугу."
            )
        except Exception as e:
            logger.error(f"Ошибка при обработке start параметра: {e}")
            await update.message.reply_text(
                "Привет! Я бот для онлайн-записи. Используйте /book, чтобы записаться на услугу."
            )
    else:
        await update.message.reply_text(
            "Привет! Я бот для онлайн-записи. Используйте /book, чтобы записаться на услугу."
        )

# Команда /book


async def book(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    company_id = context.user_data.get("company_id", COMPANY_ID)
    user_id = update.effective_user.id

    # Проверяем активность интеграции
    if not is_integration_active(user_id, company_id):
        await update.message.reply_text(
            "Интеграция с YClients отключена. Пожалуйста, подключите интеграцию снова."
        )
        return
    try:
        await context.bot.delete_message(
            chat_id=update.effective_chat.id,
            message_id=update.message.message_id
        )
    except Exception as e:
        logger.warning(f"Не удалось удалить сообщение '/book': {e}")

    staff_data = get_staff(context)
    if not staff_data:
        await update.message.reply_text("Не удалось получить список сотрудников. Попробуйте позже.")
        return

    keyboard = [
        [InlineKeyboardButton(staff_member["name"],
                              callback_data=f"staff_{staff_member['id']}")]
        for staff_member in staff_data
    ]
    keyboard.append([InlineKeyboardButton(
        "Любой сотрудник", callback_data="staff_any")])
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text("Выберите сотрудника:", reply_markup=reply_markup)

# Обработка выбора сотрудника


async def choose_staff(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()

    staff_id = query.data.split("_")[1] if query.data.split("_")[
        1] != 'any' else None
    context.user_data["staff_id"] = staff_id

    services_data = get_services(context, staff_id)
    if not services_data:
        await query.edit_message_text("Не удалось получить список услуг. Попробуйте позже.")
        return

    keyboard = [
        [InlineKeyboardButton(
            f"{service['title']} - {service.get('price_min', 'Неизвестно')} руб.", callback_data=f"service_{service['id']}")]
        for service in services_data
    ]
    keyboard.append([InlineKeyboardButton(
        "Назад", callback_data="back_to_staff")])
    reply_markup = InlineKeyboardMarkup(keyboard)

    await query.edit_message_text("Выберите услугу:", reply_markup=reply_markup)

# Обработка выбора услуги


async def choose_service(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()

    service_id = int(query.data.split("_")[1])
    context.user_data["service_id"] = service_id

    services_data = get_services(context)
    context.user_data["service_name"] = next(
        (s["title"] for s in services_data if s["id"] == service_id), "Неизвестная услуга")
    if context.user_data["service_name"] == "Неизвестная услуга":
        logger.warning(f"Не удалось найти услугу с ID {service_id}")

    staff_id = context.user_data.get("staff_id")
    available_dates = get_available_days(context, service_id, staff_id)
    if not available_dates:
        await query.edit_message_text("Не удалось получить доступные даты. Попробуйте позже.")
        return

    # Группируем даты по месяцам
    months = {}
    for date_str in available_dates:
        date_obj = datetime.strptime(date_str, "%Y-%m-%d").date()
        month_year = date_obj.strftime("%B %Y")  # Полное название месяца и год
        if month_year not in months:
            months[month_year] = []
        months[month_year].append(date_str)

    context.user_data["available_months"] = months

    keyboard = [
        [InlineKeyboardButton(translate_month_to_russian(
            month_year), callback_data=f"month_{month_year}")]
        for month_year in months.keys()
    ]
    keyboard.append([InlineKeyboardButton(
        "Назад", callback_data="back_to_services")])
    reply_markup = InlineKeyboardMarkup(keyboard)

    await query.edit_message_text("Выберите месяц:", reply_markup=reply_markup)

# Обработка выбора месяца


async def choose_month(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()

    selected_month_year = query.data.split("_")[1]
    context.user_data["selected_month_year"] = selected_month_year

    # Получаем даты для выбранного месяца
    available_dates = context.user_data["available_months"][selected_month_year]

    keyboard = []
    row = []
    for date_str in available_dates:
        date_obj = datetime.strptime(date_str, "%Y-%m-%d").date()
        day = date_obj.strftime("%d")  # Получаем только число
        weekday = get_weekday_russian(date_obj)  # Получаем день недели
        button_text = f"{day} ({weekday})"  # Формируем текст кнопки
        button = InlineKeyboardButton(
            button_text, callback_data=f"date_{date_str}")
        row.append(button)
        if len(row) == 3:  # Максимум 3 кнопки в строке
            keyboard.append(row)
            row = []
    if row:  # Добавляем последний неполный ряд
        keyboard.append(row)

    keyboard.append([InlineKeyboardButton(
        "Назад", callback_data="back_to_months")])  # Кнопка "Назад"
    reply_markup = InlineKeyboardMarkup(keyboard)

    await query.edit_message_text(f"Выберите дату в {translate_month_to_russian(selected_month_year)}:", reply_markup=reply_markup)


# Обработка выбора даты
async def choose_date(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()

    selected_date = query.data.split("_")[1]
    context.user_data["selected_date"] = selected_date

    staff_id = context.user_data.get("staff_id")
    service_id = context.user_data["service_id"]
    available_times = get_available_times(
        context, service_id, staff_id, selected_date)
    if not available_times:
        await query.edit_message_text("Не удалось получить доступное время. Попробуйте позже.")
        return

    keyboard = []
    row = []
    for i, time in enumerate(available_times):
        button = InlineKeyboardButton(
            time['time'], callback_data=f"time_{time['time']}")
        row.append(button)
        # 4 кнопки в строке или последний элемент
        if (i + 1) % 4 == 0 or i == len(available_times) - 1:
            keyboard.append(row)
            row = []

    keyboard.append([InlineKeyboardButton(
        "Назад", callback_data="back_to_dates")])
    reply_markup = InlineKeyboardMarkup(keyboard)

    context.user_data["choose_time_message_id"] = query.message.message_id

    await query.edit_message_text("Выберите время:", reply_markup=reply_markup)


# Обработка выбора времени
async def choose_time(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()

    selected_time = query.data.split("_")[1]
    context.user_data["selected_time"] = selected_time

    try:
        await context.bot.delete_message(
            chat_id=update.effective_chat.id,
            message_id=context.user_data["choose_time_message_id"]
        )
    except Exception as e:
        logger.warning(f"Не удалось удалить сообщение 'Выберите время:': {e}")

    user_id = str(update.effective_user.id)
    phone = get_user_phone(user_id)

    if phone:
        context.user_data["phone"] = phone
        await confirm_booking(update, context)
    else:
        keyboard = [
            [KeyboardButton("Отправить номер телефона", request_contact=True)]]
        reply_markup = ReplyKeyboardMarkup(
            keyboard, one_time_keyboard=True, resize_keyboard=True)

        phone_request_message = await update.effective_chat.send_message(
            "Пожалуйста, отправьте ваш номер телефона, используя кнопку 'Отправить номер телефона'.",
            reply_markup=reply_markup
        )

        context.user_data["phone_request_message_id"] = phone_request_message.message_id


# Обработка ввода номера телефона
async def handle_phone(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message.contact:
        phone = update.message.contact.phone_number
    else:
        reject_message = await update.message.reply_text("Пожалуйста, отправьте ваш номер телефона, используя кнопку 'Отправить номер телефона'.")
        context.user_data["reject_message_id"] = reject_message.message_id
        return

    if not phone:
        await update.message.reply_text("Не удалось получить номер телефона. Попробуйте еще раз.")
        return

    context.user_data["phone"] = phone

    user_id = str(update.effective_user.id)
    save_user_phone(user_id, phone)

    try:
        await context.bot.delete_message(
            chat_id=update.effective_chat.id,
            message_id=context.user_data["phone_request_message_id"]
        )
    except Exception as e:
        logger.warning(
            f"Не удалось удалить сообщение с запросом телефона: {e}")

    try:
        await context.bot.delete_message(
            chat_id=update.effective_chat.id,
            message_id=update.message.message_id
        )
    except Exception as e:
        logger.warning(
            f"Не удалось удалить сообщение пользователя с телефоном: {e}")

    if "reject_message_id" in context.user_data:
        try:
            await context.bot.delete_message(
                chat_id=update.effective_chat.id,
                message_id=context.user_data["reject_message_id"]
            )
        except Exception as e:
            logger.warning(
                f"Не удалось удалить сообщение об отклонении ручного ввода номера: {e}")
        del context.user_data["reject_message_id"]

    await confirm_booking(update, context)


# Подтверждение записи
async def confirm_booking(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    staff_id = context.user_data.get("staff_id")
    service_id = context.user_data["service_id"]
    selected_date = context.user_data["selected_date"]

    try:
        date_object = datetime.strptime(selected_date, "%Y-%m-%d")
        formatted_date = date_object.strftime("%d-%m-%Y")
    except ValueError:
        formatted_date = selected_date

    selected_time = context.user_data["selected_time"]
    phone = context.user_data["phone"]
    service_name = context.user_data["service_name"]

    if staff_id:
        staff_data = get_staff(context)
        if staff_data:
            staff_member = next(
                (s for s in staff_data if str(s["id"]) == staff_id), None)
            if staff_member:
                staff_name = staff_member["name"]
            else:
                staff_name = "Неизвестный сотрудник"
                logger.warning(f"Не удалось найти сотрудника с ID {staff_id}")
        else:
            staff_name = "Неизвестный сотрудник"
            logger.warning("Не удалось получить список сотрудников.")
    else:
        staff_name = "Любой сотрудник"

    message = (
        "<b>Проверьте данные:</b>\n"
        f"Сотрудник: {staff_name}\n"
        f"Услуга: {service_name}\n"
        f"Дата: {formatted_date}\n"
        f"Время: {selected_time}\n"
        f"Ваше имя: {update.effective_user.full_name}\n"
        f"Телефон: {phone}"
    )

    keyboard = [
        [InlineKeyboardButton("Изменить", callback_data="change_booking")],
        [InlineKeyboardButton(
            "Оформить запись", callback_data="confirm_booking_final")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.effective_chat.send_message(
        message,
        reply_markup=reply_markup,
        parse_mode=constants.ParseMode.HTML
    )

# Обработчик для кнопки "Изменить"


async def change_booking(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    keyboard = [
        [InlineKeyboardButton("Изменить Сотрудника",
                              callback_data="change_staff")],
        [InlineKeyboardButton(
            "Изменить Услугу", callback_data="change_service")],
        [InlineKeyboardButton("Изменить Дату", callback_data="change_date")],
        [InlineKeyboardButton("Изменить Время", callback_data="change_time")],
        [InlineKeyboardButton("Изменить Телефон",
                              callback_data="change_phone")],
        [InlineKeyboardButton("Отмена", callback_data="back_to_confirmation")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await query.edit_message_text("Что вы хотите изменить?", reply_markup=reply_markup)

# Обработчик кнопки "Отмена"


async def back_to_confirmation(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    await confirm_booking(update, context)

# Обработчик для кнопки "Изменить телефон"


async def change_phone(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    keyboard = [
        [KeyboardButton("Отправить номер телефона", request_contact=True)]]
    reply_markup = ReplyKeyboardMarkup(
        keyboard, one_time_keyboard=True, resize_keyboard=True)

    phone_request_message = await update.effective_chat.send_message(
        "Пожалуйста, отправьте ваш новый номер телефона, используя кнопку 'Отправить номер телефона'.",
        reply_markup=reply_markup
    )

    context.user_data["phone_request_message_id"] = phone_request_message.message_id


# Обработчики для кнопок "Изменить..."
async def change_staff(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    staff_data = get_staff(context)
    if not staff_data:
        await query.edit_message_text("Не удалось получить список сотрудников. Попробуйте позже.")
        return

    keyboard = [
        [InlineKeyboardButton(staff_member["name"],
                              callback_data=f"staff_{staff_member['id']}")]
        for staff_member in staff_data
    ]
    keyboard.append([InlineKeyboardButton(
        "Любой сотрудник", callback_data="staff_any")])
    reply_markup = InlineKeyboardMarkup(keyboard)

    await query.edit_message_text("Выберите сотрудника:", reply_markup=reply_markup)


async def change_service(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    staff_id = context.user_data.get("staff_id")
    services_data = get_services(context, staff_id)
    if not services_data:
        await query.edit_message_text("Не удалось получить список услуг. Попробуйте позже.")
        return

    keyboard = [
        [InlineKeyboardButton(
            f"{service['title']} - {service.get('price_min', 'Неизвестно')} руб.", callback_data=f"service_{service['id']}")]
        for service in services_data
    ]
    keyboard.append([InlineKeyboardButton(
        "Назад", callback_data="back_to_staff")])
    reply_markup = InlineKeyboardMarkup(keyboard)

    await query.edit_message_text("Выберите услугу:", reply_markup=reply_markup)


async def change_date(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    service_id = context.user_data["service_id"]
    staff_id = context.user_data.get("staff_id")
    available_dates = get_available_days(context, service_id, staff_id)
    if not available_dates:
        await query.edit_message_text("Не удалось получить доступные даты. Попробуйте позже.")
        return

    # Группируем даты по месяцам
    months = {}
    for date_str in available_dates:
        date_obj = datetime.strptime(date_str, "%Y-%m-%d").date()
        month_year = date_obj.strftime("%B %Y")  # Полное название месяца и год
        if month_year not in months:
            months[month_year] = []
        months[month_year].append(date_str)

    context.user_data["available_months"] = months

    keyboard = [
        [InlineKeyboardButton(translate_month_to_russian(
            month_year), callback_data=f"month_{month_year}")]
        for month_year in months.keys()
    ]
    keyboard.append([InlineKeyboardButton(
        "Назад", callback_data="back_to_services")])
    reply_markup = InlineKeyboardMarkup(keyboard)

    await query.edit_message_text("Выберите месяц:", reply_markup=reply_markup)


async def change_time(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    selected_date = context.user_data["selected_date"]
    staff_id = context.user_data.get("staff_id")
    service_id = context.user_data["service_id"]
    available_times = get_available_times(
        context, service_id, staff_id, selected_date)
    if not available_times:
        await query.edit_message_text("Не удалось получить доступное время. Попробуйте позже.")
        return

    keyboard = []
    row = []
    for i, time in enumerate(available_times):
        button = InlineKeyboardButton(
            time['time'], callback_data=f"time_{time['time']}")
        row.append(button)
        if (i + 1) % 4 == 0:  # 4 кнопки в строке
            keyboard.append(row)
            row = []
    if row:  # Добавляем оставшиеся кнопки, если их меньше 4
        keyboard.append(row)

    keyboard.append([InlineKeyboardButton(
        "Назад", callback_data="back_to_dates")])
    reply_markup = InlineKeyboardMarkup(keyboard)

    context.user_data["choose_time_message_id"] = query.message.message_id

    await query.edit_message_text("Выберите время:", reply_markup=reply_markup)

# Обработчик для отклонения ручного ввода номера телефона


async def reject_manual_phone(update: Update, context: ContextTypes.DEFAULT_TYPE):
    reject_message = await update.message.reply_text("Пожалуйста, отправьте ваш номер телефона, используя кнопку 'Отправить номер телефона'.")
    context.user_data["reject_message_id"] = reject_message.message_id


async def confirm_booking_final(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await create_booking(update, context)


async def back_to_staff(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    staff_data = get_staff(context)
    if not staff_data:
        await query.edit_message_text("Не удалось получить список сотрудников. Попробуйте позже.")
        return

    keyboard = [
        [InlineKeyboardButton(staff_member["name"],
                              callback_data=f"staff_{staff_member['id']}")]
        for staff_member in staff_data
    ]
    keyboard.append([InlineKeyboardButton(
        "Любой сотрудник", callback_data="staff_any")])
    reply_markup = InlineKeyboardMarkup(keyboard)

    await query.edit_message_text("Выберите сотрудника:", reply_markup=reply_markup)


async def back_to_services(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    staff_id = context.user_data.get("staff_id")
    services_data = get_services(context, staff_id)
    if not services_data:
        await query.edit_message_text("Не удалось получить список услуг. Попробуйте позже.")
        return

    keyboard = [
        [InlineKeyboardButton(
            f"{service['title']} - {service.get('price_min', 'Неизвестно')} руб.", callback_data=f"service_{service['id']}")]
        for service in services_data
    ]
    keyboard.append([InlineKeyboardButton(
        "Назад", callback_data="back_to_staff")])
    reply_markup = InlineKeyboardMarkup(keyboard)

    await query.edit_message_text("Выберите услугу:", reply_markup=reply_markup)


async def back_to_dates(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    # Возвращаемся к выбору месяца
    await change_date(update, context)


async def back_to_months(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    service_id = context.user_data["service_id"]
    staff_id = context.user_data.get("staff_id")
    available_dates = get_available_days(context, service_id, staff_id)
    if not available_dates:
        await query.edit_message_text("Не удалось получить доступные даты. Попробуйте позже.")
        return

    # Группируем даты по месяцам
    months = {}
    for date_str in available_dates:
        date_obj = datetime.strptime(date_str, "%Y-%m-%d").date()
        month_year = date_obj.strftime("%B %Y")  # Полное название месяца и год
        if month_year not in months:
            months[month_year] = []
        months[month_year].append(date_str)

    context.user_data["available_months"] = months

    keyboard = [
        [InlineKeyboardButton(translate_month_to_russian(
            month_year), callback_data=f"month_{month_year}")]
        for month_year in months.keys()
    ]
    keyboard.append([InlineKeyboardButton(
        "Назад", callback_data="back_to_services")])
    reply_markup = InlineKeyboardMarkup(keyboard)

    await query.edit_message_text("Выберите месяц:", reply_markup=reply_markup)


# Обработка подтверждения записи
async def create_booking(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()

    staff_id = context.user_data.get("staff_id")
    service_id = context.user_data["service_id"]
    selected_date = context.user_data["selected_date"]

    try:
        date_object = datetime.strptime(selected_date, "%Y-%m-%d")
        formatted_date = date_object.strftime("%d-%m-%Y")
    except ValueError:
        formatted_date = selected_date

    selected_time = context.user_data["selected_time"]
    phone = context.user_data["phone"]
    email = "user@example.com"  # TODO: Запросить email у пользователя
    service_name = context.user_data["service_name"]

    try:
        date_time_str = f"{selected_date} {selected_time}"
        date_time_obj = datetime.strptime(
            date_time_str, "%Y-%m-%d %H:%M")
        formatted_date_time = date_time_obj.strftime(
            "%Y-%m-%d %H:%M:%S")
    except ValueError as e:
        logger.error(f"Ошибка при форматировании даты и времени: {e}")
        await query.edit_message_text("Некорректный формат даты или времени. Попробуйте еще раз.")
        return

    booking_data = {
        "booking_id": 0,
        "fullname": update.effective_user.full_name,
        "phone": phone,
        "email": email,
        "service_id": service_id,
        "date_time": formatted_date_time,
        "staff_id": staff_id,
        "comment": "Запись через Telegram-бота",
    }

    try:
        company_id = context.user_data.get("company_id", COMPANY_ID)
        form_id = context.user_data.get("form_id", FORM_ID)

        logger.info(
            f"Создание записи с параметрами: company_id={company_id}, form_id={form_id}")
        logger.info(f"Данные для записи: {booking_data}")

        api = YClientsAPI(token=YCLIENTS_API_TOKEN,
                          company_id=company_id, form_id=form_id)
        booked = api.book(**booking_data)

        logger.info(f"Ответ API при создании записи: {booked}")
        logger.debug(f"API Response: {booked}")
        logger.info(f"BOOKED: {booked}")

        if isinstance(booked, tuple) and booked[0] is True:
            staff_id_for_name = context.user_data.get("staff_id")
            if staff_id_for_name:
                staff_data = get_staff(context)
                if staff_data:
                    staff_member = next((s for s in staff_data if str(
                        s["id"]) == staff_id_for_name), None)
                    staff_name = staff_member["name"] if staff_member else "Неизвестный сотрудник"
                else:
                    staff_name = "Неизвестный сотрудник"
            else:
                staff_name = "Любой сотрудник"

            confirmation_message = (
                "<b>Запись подтверждена!</b>\n"
                f"Дата: {formatted_date}\n"
                f"Время: {selected_time}\n"
                f"Услуга: {service_name}\n"
                f"Сотрудник: {staff_name}"
            )
            await query.edit_message_text(confirmation_message, parse_mode=constants.ParseMode.HTML)

            context.user_data.clear()
        else:
            error_message = "Неизвестная ошибка при создании записи."
            if isinstance(booked, tuple) and len(booked) > 1:
                error_message = booked[1]

            await query.edit_message_text(f"Произошла ошибка при создании записи: {error_message}")

    except Exception as e:
        logger.error(f"Ошибка при создании записи: {e}")
        await query.edit_message_text("Произошла ошибка при создании записи. Попробуйте позже.")

# Запуск бота


def main():
    application = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("book", book))

    application.add_handler(CallbackQueryHandler(
        choose_staff, pattern="^staff_"))
    application.add_handler(CallbackQueryHandler(
        choose_service, pattern="^service_"))
    application.add_handler(CallbackQueryHandler(
        choose_month, pattern="^month_"))
    application.add_handler(CallbackQueryHandler(
        choose_date, pattern="^date_"))
    application.add_handler(CallbackQueryHandler(
        choose_time, pattern="^time_"))
    application.add_handler(CallbackQueryHandler(
        confirm_booking_final, pattern="^confirm_booking_final"))
    application.add_handler(CallbackQueryHandler(
        back_to_staff, pattern="^back_to_staff"))
    application.add_handler(CallbackQueryHandler(
        back_to_services, pattern="^back_to_services"))
    application.add_handler(CallbackQueryHandler(
        back_to_dates, pattern="^back_to_dates"))
    application.add_handler(CallbackQueryHandler(
        back_to_months, pattern="^back_to_months"))
    application.add_handler(CallbackQueryHandler(
        change_booking, pattern="^change_booking"))
    application.add_handler(CallbackQueryHandler(
        change_staff, pattern="^change_staff"))
    application.add_handler(CallbackQueryHandler(
        change_service, pattern="^change_service"))
    application.add_handler(CallbackQueryHandler(
        change_date, pattern="^change_date"))
    application.add_handler(CallbackQueryHandler(
        change_time, pattern="^change_time"))
    application.add_handler(CallbackQueryHandler(
        change_phone, pattern="^change_phone"))
    application.add_handler(CallbackQueryHandler(
        back_to_confirmation, pattern="^back_to_confirmation"))

    application.add_handler(MessageHandler(filters.CONTACT, handle_phone))
    application.add_handler(MessageHandler(
        filters.TEXT & ~filters.COMMAND & ~filters.CONTACT, reject_manual_phone))

    application.run_polling()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Бот остановлен вручную (Ctrl+C).")
    except Exception as e:
        logger.error(f"Ошибка: {e}")
