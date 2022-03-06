public class EuclideanAlgorithm
{

    /**
     * Uses Euclidean algorithm to return the greatest common divisor (gcd) of two
     * integers
     */
    public static int gcd(int a, int b)
    {
        // Set int a and int b to be positive if not already
        a = Math.abs(a);
        b = Math.abs(b);

        while (b != 0)
        {
            int r = a % b;
            a = b;
            b = r;
        }

        return a;
    }

    public static void main(String[] args)
    {
        System.out.println(gcd(7469, -2464));
        System.out.println(gcd(2689, -4001));
        System.out.println(gcd(144, 12));
        System.out.println(gcd(-144, 12));
        System.out.println(gcd(144, -12));
        System.out.println(gcd(-144, -12));
    }

}