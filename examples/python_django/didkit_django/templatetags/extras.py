import json

from django import template

register = template.Library()


@register.filter
def pretty_json(value):
    return json.dumps(value, indent=2, sort_keys=True)
