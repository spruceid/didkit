from qr_code.qrcode.maker import make_qr_code_with_args
from django import template

register = template.Library()


@register.simple_tag()
def qr_from_text(text, **kwargs) -> str:
    return make_qr_code_with_args(text, qr_code_args=kwargs)
