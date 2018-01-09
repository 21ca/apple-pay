# apple-pay
Speed up your Apple Pay development

Apple Pay Payment Token Format Reference, please refer to: https://developer.apple.com/library/content/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html

ApplePayStartSession: used to start a transaction. The response need to be returned to the JS call back method "onvalidatemerchant".

ApplePayDecoder: used to decode the card number based on ApplePay authorization response, which comes from JS call back method "onpaymentauthorized".

ApplePaySignatureVerifier: used to verify the signature based on ApplePay authorization response. It's not working and is under development now.