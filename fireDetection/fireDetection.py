import numpy as np
import cv2

face_cascade = cv2.CascadeClassifier('haarcascade_frontalface_default.xml')
eye_cascade = cv2.CascadeClassifier('haarcascade_eye.xml')

fire_cascade = cv2.CascadeClassifier('cascade.xml')

img = cv2.imread('9.jpg')
while 1:
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    fires = fire_cascade.detectMultiScale(gray, 50, 50)
    
    for (x,y,w,h) in fires:
        font = cv2.FONT_HERSHEY_SIMPLEX
        cv2.putText(img,'Fire',(x-w,y-h), font, 1.5, (0,0,0), 2, cv2.LINE_AA)

    cv2.imshow('img',img)
    k = cv2.waitKey(30) & 0xff
    if k == 27:
        break

cap.release()
cv2.destroyAllWindows()