from django import forms

class ContactForm(forms.Form):
    text = forms.CharField()
