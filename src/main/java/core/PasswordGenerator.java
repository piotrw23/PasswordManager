package core;

import java.security.SecureRandom;

public class PasswordGenerator {
    private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String DIGITS = "0123456789";
    private static final String SPECIALS = "!@#$%^&*()-_=+[]{}|;:,.<>?/";

    private static final String ALL_CHARACTERS = LOWERCASE + UPPERCASE + DIGITS + SPECIALS;
    private final SecureRandom secureRandom = new SecureRandom();

    public char[] generatePassword(int length) {
        if(length < 8) {
            throw new IllegalArgumentException("Hasło musi zawierać co najmniej 8 znaków.");
        }

        boolean isValid = false;
        char[] password = new char[length];

        while(!isValid) {
            for(int i = 0; i < length; i++) {
                int randomIdx = secureRandom.nextInt(ALL_CHARACTERS.length());
                password[i] = ALL_CHARACTERS.charAt(randomIdx);
            }

            isValid = checkConstraints(password);
        }

        return password;
    }

    // checks if generated password is safe
    private boolean checkConstraints(char[] password) {
        boolean hasDigit = false;
        boolean hasSpecial = false;

        for(char c : password) {
            if(DIGITS.indexOf(c) >= 0) hasDigit = true;
            if(SPECIALS.indexOf(c) >= 0) hasSpecial = true;

            if(hasDigit && hasSpecial) return true;
        }

        return false;
    }

    public double computeEntropy(int length) {
        int r = ALL_CHARACTERS.length();
        return length * (Math.log(r) / Math.log(2));
    }
}
