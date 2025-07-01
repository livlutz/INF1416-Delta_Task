
/*Determinar o código secreto referente ao criptograma com a técnica de força bruta
que receba a semente da chave criptográfica (arg[0]), o texto plano parcial (arg[1])
e o criptograma em hexadecimal (arg[2])) na linha de argumento.
As informações fornecidas pelo agente Brasília (algoritmo criptográfico e semente da chave criptográfica)
e pelo setor de investigação (texto plano parcial) são cruciais para essa missão. */

/*IV encontrado: 0000000693920323*/
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import javax.crypto.KeyGenerator;
import java.util.Arrays;

public class Desafio_Livia_2211055 {

    private static byte[] get_chave(String semente) throws Exception {
        // Cria um SecureRandom com SHA1PRNG
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(semente.getBytes("UTF-8"));

        // Cria o KeyGenerator para AES e inicializa com 128 bits
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128, sr);

        // Gera a chave secreta
        SecretKeySpec key = new SecretKeySpec(kg.generateKey().getEncoded(), "AES");
        return key.getEncoded();
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                + Character.digit(s.charAt(i+1), 16));
        return data;
    }

    private static String decifra_texto(byte[] chave, byte[] dados, String ivString) throws Exception {
        byte[] ivBytes = ivString.getBytes("UTF-8");
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        // Cria o Cipher para AES/CBC/PKCS5Padding
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(chave, "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);

        byte[] decrypted = cipher.doFinal(dados);
        return new String(decrypted, "UTF-8");
    }

    public void get_codigo(String semente, String texto_plano_parcial, String criptograma) throws Exception {

        /*ii) os códigos secretos correspondem respectivamente aos valores IV (Initialization Vector) de cada um dos criptogramas;*/

        int i = 0;

        while (true) {
            System.out.println("IV: " + i);
            String ivString = String.format("%016d", i);

            try{
                // Decifra o texto usando o IV atual
                byte[] chave = get_chave(semente);
                byte[] dados = hexStringToByteArray(criptograma);
                String decryptedText = decifra_texto(chave, dados, ivString);
                // Verifica se o texto decifrado contém o texto plano parcial
                if (decryptedText.contains(texto_plano_parcial)) {
                    // Retorna o IV como código secreto
                    System.out.println("IV encontrado: " + ivString);
                    break;
                }
                i++;
            }

            catch(Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args){

        /*Agente Brasilia usou o alfabeto fonetico mundial :
        *   00: ALFA ECHO SIERRA UNO DOIS OITO
            01: CHARLIE BETA CHARLIE
            02: PAPA KILO CHARLIE SIERRA CINCO
            03: KILO ECHO YANKEE SIERRA ECHO ECHO DELTA
            04: SIERRA KILO YANKEE WHISKEY ALFA LIMA KILO ECHO ROMA UNO NOVE OITO ZERO
            05: INDIA VICTOR
            07: PAPA ROMA NOVEMBER GOLF
            08: SIERRA HOTEL ALFA UNO

            00: AES 128
            01: CBC
            02: PKCS5
            03: KEYSEED
            04: SKYWALKER1980
            05: IV
            06: .....
            07: PRNG
            08: SHA1
        */

        /*informacoes pelo setor de investigacao (texto plano parcial arg[1])
        Star Wars: Episode
        */

        /*criptograma em hexadecimal (arg[2]):
        * 41ed229995eba532f0623431cc5760286f8b75bbdc421946cc2f485fb39b90cef244c4
            1a07c958ae6a56dd1b34aad25226b61f7e2fa41f36e678bcb139ab667a26407f973995
            10ce941aff5a9e7b8322880cd58af14e0a2e26e6dc785238041ece280da8571e5d2468
            708b975588a2dd
        */

        /*1o Relatório:
        Na avaliação do setor de investigação e análises da Delta-Info,
        (i) todos os criptogramas têm uma probalidade de 99,9% de serem gerados a partir de textos planos contendo o texto "Star Wars: Episode";
        (ii) os códigos secretos correspondem respectivamente aos valores IV (Initialization Vector) de cada um dos criptogramas;
        e (iii) os códigos secretos são formados apenas por caracteres numéricos de 0 a 9 (vetor de caracteres ASCII).
        Esse setor da Delta-Info tem grau de confiabilidade superior a 95% em todas as suas análises. */

        String semente = args[0];
        String texto_plano_parcial = args[1];
        String criptograma = args[2];
        Desafio desafio = new Desafio();
        try {
            desafio.get_codigo(semente, texto_plano_parcial, criptograma);
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
}
