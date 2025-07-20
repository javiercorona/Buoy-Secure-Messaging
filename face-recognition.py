"""
FaceLock plugin – requires authorized face match to decrypt messages.
"""
import face_recognition
import cv2
import numpy as np
from typing import Tuple, Dict, Any
from Buoy import BuoyPlugin  # Make sure BuoyPlugin is importable from the main module

class FaceLock(BuoyPlugin):
    version = "0.1"
    
    def __init__(self, cipher):
        super().__init__(cipher)
        try:
            self.known_face = np.load("face_embedding.npy")
            self.available = True
        except Exception:
            self.available = False

    def pre_decrypt(self, ciphertext: bytes, context: Dict[str, Any]) -> Tuple[bytes, Dict[str, Any]]:
        if not self.available:
            raise RuntimeError("FaceLock: No authorized face found.")
        
        cam = cv2.VideoCapture(0)
        print("FaceLock: Please look into the camera...")
        ret, frame = cam.read()
        cam.release()
        
        encodings = face_recognition.face_encodings(frame)
        if not encodings:
            raise RuntimeError("FaceLock: No face detected.")
        
        if face_recognition.compare_faces([self.known_face], encodings[0])[0]:
            print("FaceLock: Face match successful.")
            return ciphertext, context
        else:
            raise PermissionError("FaceLock: Unauthorized face detected.")

    def get_metadata(self) -> Dict[str, Any]:
        return {
            "name": "FaceLock",
            "version": self.version,
            "description": "Requires face match before message decryption."
        }
