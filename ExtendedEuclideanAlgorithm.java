public class ExtendedEuclideanAlgorithm
{

    /**
     * Uses Extended Euclidean algorithm to return the inverse of b mod n where b is
     * an integer and n is a positive integer
     */
    public static int inverse(int b, int n)
    {
        System.out.println("Finding inverse of " + b + " mod " + n + "...");
        int p = 0, newP = 1, a = n, q, r, tempP = -1;
        // b = a;

        while (b != 0)
        {
            q = a / b;
            System.out.println("Quotient: " + q);
            r = a % b;
            System.out.println("Remainder: " + r);
            if (Math.abs(b) == 1) // catches if EEA has a b is already 1 (or negative 1) in step 0.
            {
                System.out.println("The inverse is: " + newP + "\n");
                return newP;
            }

            if (p - newP * q < 0)
                tempP = ((p - newP * q) % n) + n; // actually has to be 'real' modulo
            else
                tempP = (p - newP * q) % n; // else standard remainder operator works

            p = newP;
            newP = tempP;
            a = b;
            b = r;

            if (Math.abs(b) == 1)
            {
                System.out.println("The inverse is: " + newP + "\n");
                return newP;
            }
        }

        // if(a>1) {
        System.out.println("There is no inverse.\n");
        return -1;
        // }
    }

    public static void main(String[] args)
    {
        inverse(7, 26);
        inverse(19, 999);
        inverse(5, 8);
        inverse(1, 1);
        inverse(-1, 1);
        inverse(2, 6);
        inverse(28, 29);
    }
}