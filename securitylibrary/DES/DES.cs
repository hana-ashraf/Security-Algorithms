using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            int[,] PC_1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9 }, { 1, 58, 50, 42, 34, 26, 18 }, { 10, 2, 59, 51, 43, 35, 27 }, { 19, 11, 3, 60, 52, 44, 36 }, { 63, 55, 47, 39, 31, 23, 15 }, { 7, 62, 54, 46, 38, 30, 22 }, { 14, 6, 61, 53, 45, 37, 29 }, { 21, 13, 5, 28, 20, 12, 4 } };

            int[,] PC_2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 }, { 3, 28, 15, 6, 21, 10 }, { 23, 19, 12, 4, 26, 8 }, { 16, 7, 27, 20, 13, 2 }, { 41, 52, 31, 37, 47, 55 }, { 30, 40, 51, 45, 33, 48 }, { 44, 49, 39, 56, 34, 53 }, { 46, 42, 50, 36, 29, 32 } };

            int[,] s1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
            int[,] s2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
            int[,] s3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
            int[,] s4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
            int[,] s5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
            int[,] s6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
            int[,] s7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
            int[,] s8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

            int[,] P = new int[8, 4] { { 16, 7, 20, 21 }, { 29, 12, 28, 17 }, { 1, 15, 23, 26 }, { 5, 18, 31, 10 }, { 2, 8, 24, 14 }, { 32, 27, 3, 9 }, { 19, 13, 30, 6 }, { 22, 11, 4, 25 } };

            int[,] EB = new int[8, 6] { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 }, { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 }, { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 }, { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };

            int[,] IP = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10, 2 }, { 60, 52, 44, 36, 28, 20, 12, 4 }, { 62, 54, 46, 38, 30, 22, 14, 6 }, { 64, 56, 48, 40, 32, 24, 16, 8 }, { 57, 49, 41, 33, 25, 17, 9, 1 }, { 59, 51, 43, 35, 27, 19, 11, 3 }, { 61, 53, 45, 37, 29, 21, 13, 5 }, { 63, 55, 47, 39, 31, 23, 15, 7 } };

            int[,] IP_1 = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 }, { 39, 7, 47, 15, 55, 23, 63, 31 }, { 38, 6, 46, 14, 54, 22, 62, 30 }, { 37, 5, 45, 13, 53, 21, 61, 29 }, { 36, 4, 44, 12, 52, 20, 60, 28 }, { 35, 3, 43, 11, 51, 19, 59, 27 }, { 34, 2, 42, 10, 50, 18, 58, 26 }, { 33, 1, 41, 9, 49, 17, 57, 25 } };


            string bicipher = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(64, '0');
            string bikey = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');

            string Lm = "";
            string Rm = "";

            //for (int i = 0; i < bicipher.Length / 2; i++) // b2sm el cipher bta3y nosen left w right
            //{
            //    Lm = Lm + bicipher[i];
            //    Rm = Rm + bicipher[i + bicipher.Length / 2];
            //}

            //premutate key by pc-1
            string tmpk = "";
            List<string> C = new List<string>();
            List<string> D = new List<string>();

            for (int i = 0; i < 8; i++) // bd5l el key 3la el permutation matrix pc1 (inverse matrix) 56 bit
            {
                for (int j = 0; j < 7; j++)
                {
                    tmpk = tmpk + bikey[PC_1[i, j] - 1];
                }
            }

            //C and D
            string c = tmpk.Substring(0, 28);//b2sm el key l right w left
            string d = tmpk.Substring(28, 28);

            string temp = "";
            for (int i = 0; i <= 16; i++) //bm4y 3la 3dd el rounds
            {
                C.Add(c);// b7ot el left fe C
                D.Add(d);//b7ot el right fe D
                temp = "";
                if (i == 0 || i == 1 || i == 8 || i == 15) // lw 0 aw 1 ... shift left num bta3hom 1 y3ni h4ft mra wa7da bs 
                {
                    temp = temp + c[0]; // b7ot awl rkm fe temp a7tfz beh
                    c = c.Remove(0, 1);//w a3mlo remove
                    c = c + temp;//w a7to fe a5r el c
                    temp = ""; //w bfdy el temp tany 
                    temp = temp + d[0];// w b3ml nfs el klam m3 el right
                    d = d.Remove(0, 1);
                    d = d + temp;
                }

                else // tb lw aktr mn mra shiftleft
                {
                    temp = temp + c.Substring(0, 2);
                    c = c.Remove(0, 2);
                    c = c + temp;
                    temp = "";
                    temp = temp + d.Substring(0, 2);
                    d = d.Remove(0, 2);
                    d = d + temp;
                }
            }

            List<string> keys = new List<string>();
            for (int i = 0; i < D.Count; i++)//concatenate
            {
                keys.Add(C[i] + D[i]); 
            }

            //k1 --> k16 by pc-2
            List<string> nkeys = new List<string>();
            for (int k = 1; k < keys.Count; k++)//bd5lha 3la el pc_2
            {
                tmpk = "";
                temp = "";
                temp = keys[k];
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 6; j++)
                    {
                        tmpk = tmpk + temp[PC_2[i, j] - 1];
                    }
                }

                nkeys.Add(tmpk);
            }
            //5lst kol el operations 3la el key
            //premutation by IP for plain text
            string ip = "";
            for (int i = 0; i < 8; i++)//bd5l el cipher 3la ip
            {
                for (int j = 0; j < 8; j++)
                {
                    ip = ip + bicipher[IP[i, j] - 1];
                }
            }

            List<string> L = new List<string>();
            List<string> R = new List<string>();

            string l = ip.Substring(0, 32);//w b2smo
            string r = ip.Substring(32, 32);

            L.Add(l);
            R.Add(r);
            string x = "";
            string h = "";

            string ebit = "";
            string exork = "";
            List<string> sbox = new List<string>();
            //string sb = "";
            string t = "";
            int row = 0;
            int col = 0;
            string tsb = "";
            string pp = "";
            string lf = "";

            for (int i = 0; i < 16; i++)
            {
                L.Add(r); // w b7ot el left feha el right
                exork = "";
                ebit = "";
                lf = "";
                pp = "";
                sbox.Clear();
                tsb = "";
                col = 0;
                row = 0;
                t = "";
                for (int j = 0; j < 8; j++) // w bd5l el right 3la eb
                {
                    for (int k = 0; k < 6; k++)
                    {
                        ebit = ebit + r[EB[j, k] - 1];
                    }
                }

                for (int g = 0; g < ebit.Length; g++) // wb3mlha xor m3 key ely tl3 fo2
                {
                    exork = exork + (nkeys[nkeys.Count - 1 - i][g] ^ ebit[g]).ToString();
                }

                for (int z = 0; z < exork.Length; z = z + 6) //w b2sm hena el rkm ykon 6 arkam fe kol block
                {
                    t = "";
                    for (int y = z; y < 6 + z; y++)
                    {
                        if (6 + z <= exork.Length)
                            t = t + exork[y];
                    }

                    sbox.Add(t);
                }

                t = "";
                int sb = 0;
                for (int s = 0; s < sbox.Count; s++)//w b3d kda bd5ol 3la el sbox da bykon matrix
                {
                    t = sbox[s];
                    x = t[0].ToString() + t[5]; // awl index feha w a5r index bykon el row 
                    h = t[1].ToString() + t[2] + t[3] + t[4];// w ely fe el nos da el column 

                    row = Convert.ToInt32(x, 2); 
                    col = Convert.ToInt32(h, 2);
                    if (s == 0) // w el sb ely bytl3 da el intersection ben el row el column 
                        sb = s1[row, col];

                    if (s == 1)
                        sb = s2[row, col];

                    if (s == 2)
                        sb = s3[row, col];

                    if (s == 3)
                        sb = s4[row, col];

                    if (s == 4)
                        sb = s5[row, col];

                    if (s == 5)
                        sb = s6[row, col];

                    if (s == 6)
                        sb = s7[row, col];

                    if (s == 7)
                        sb = s8[row, col];

                    tsb = tsb + Convert.ToString(sb, 2).PadLeft(4, '0'); // w b7wlo l binary
                }

                x = "";
                h = "";
                // bd5lo 3la matrix P
                for (int k = 0; k < 8; k++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        pp = pp + tsb[P[k, j] - 1];
                    }
                }
                //b3mlo xor m3 el key
                for (int k = 0; k < pp.Length; k++)
                {
                    lf = lf + (pp[k] ^ l[k]).ToString();
                }
                //b3ml swap
                r = lf;
                l = L[i + 1];
                R.Add(r);
            }
            //b3ml concatenate
            string r16l16 = R[16] + L[16];
            string ciphertxt = "";
            for (int i = 0; i < 8; i++)// bd5lha 3la matrix IP1
            {
                for (int j = 0; j < 8; j++)
                {
                    ciphertxt = ciphertxt + r16l16[IP_1[i, j] - 1];
                }
            }
            string pt = "0x" + Convert.ToInt64(ciphertxt, 2).ToString("X").PadLeft(16, '0');
            return pt;
        }
        public override string Encrypt(string plainText, string key)
        {
            int[,] PC_1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9 }, { 1, 58, 50, 42, 34, 26, 18 }, { 10, 2, 59, 51, 43, 35, 27 }, { 19, 11, 3, 60, 52, 44, 36 }, { 63, 55, 47, 39, 31, 23, 15 }, { 7, 62, 54, 46, 38, 30, 22 }, { 14, 6, 61, 53, 45, 37, 29 }, { 21, 13, 5, 28, 20, 12, 4 } };

            int[,] PC_2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 }, { 3, 28, 15, 6, 21, 10 }, { 23, 19, 12, 4, 26, 8 }, { 16, 7, 27, 20, 13, 2 }, { 41, 52, 31, 37, 47, 55 }, { 30, 40, 51, 45, 33, 48 }, { 44, 49, 39, 56, 34, 53 }, { 46, 42, 50, 36, 29, 32 } };

            int[,] s1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
            int[,] s2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
            int[,] s3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
            int[,] s4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
            int[,] s5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
            int[,] s6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
            int[,] s7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
            int[,] s8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

            int[,] P = new int[8, 4] { { 16, 7, 20, 21 }, { 29, 12, 28, 17 }, { 1, 15, 23, 26 }, { 5, 18, 31, 10 }, { 2, 8, 24, 14 }, { 32, 27, 3, 9 }, { 19, 13, 30, 6 }, { 22, 11, 4, 25 } };
            int[,] EB = new int[8, 6] { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 }, { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 }, { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 }, { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };


            int[,] IP = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10, 2 }, { 60, 52, 44, 36, 28, 20, 12, 4 }, { 62, 54, 46, 38, 30, 22, 14, 6 }, { 64, 56, 48, 40, 32, 24, 16, 8 }, { 57, 49, 41, 33, 25, 17, 9, 1 }, { 59, 51, 43, 35, 27, 19, 11, 3 }, { 61, 53, 45, 37, 29, 21, 13, 5 }, { 63, 55, 47, 39, 31, 23, 15, 7 } };

            int[,] IP_1 = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 }, { 39, 7, 47, 15, 55, 23, 63, 31 }, { 38, 6, 46, 14, 54, 22, 62, 30 }, { 37, 5, 45, 13, 53, 21, 61, 29 }, { 36, 4, 44, 12, 52, 20, 60, 28 }, { 35, 3, 43, 11, 51, 19, 59, 27 }, { 34, 2, 42, 10, 50, 18, 58, 26 }, { 33, 1, 41, 9, 49, 17, 57, 25 } };


            string biplain = Convert.ToString(Convert.ToInt64(plainText, 16), 2).PadLeft(64, '0');
            string bikey = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');

            string Lmk = "";
            string Rgm = "";
            int leno = biplain.Length / 2;
            int i = 0;
            while (i < leno)
            {
                Lmk = Lmk + biplain[i];
                Rgm = Rgm + biplain[i + leno];
                i++;
            }

            //premutate key by pc-1
            string tmpkk = "";
            List<string> C = new List<string>();
            List<string> D = new List<string>();

            for (int m = 0; m < 8; m++) // replace each index b index el p_c
            {
                for (int j = 0; j < 7; j++)
                {
                    tmpkk = tmpkk + bikey[PC_1[m, j] - 1];
                }
            }

            //C and D
            string c = tmpkk.Substring(0, 28);//divide to left 
            string d = tmpkk.Substring(28, 28);//divide to right
            bool yesthishappen = false;
            string temp = "";
            for (int m = 0; m <= 16; m++)
            {
                C.Add(c);
                D.Add(d);
                temp = "";
                if (m == 0)
                {
                    yesthishappen = true;
                }
                else if (m == 1)
                {
                    yesthishappen = true;
                }
                else if (m == 8)
                {
                    yesthishappen = true;
                }
                else if (m == 15)
                {
                    yesthishappen = true;
                }
                else
                {
                    yesthishappen = false;
                }
                if (yesthishappen == true) // shift left mra wa7da 
                {
                    temp = temp + c[0];
                    c = c.Remove(0, 1);
                    c = c + temp;
                    temp = "";
                    temp = temp + d[0];
                    d = d.Remove(0, 1);
                    d = d + temp;
                }
                else
                {
                    temp = temp + c.Substring(0, 2);
                    c = c.Remove(0, 2);
                    c = c + temp;
                    temp = "";
                    temp = temp + d.Substring(0, 2);
                    d = d.Remove(0, 2);
                    d = d + temp;
                }
            }

            List<string> keys = new List<string>();
            for (int m = 0; m < D.Count; m++) // concatenate
            {
                keys.Add(C[m] + D[m]);
            }

            //k1 --> k16 by pc-2
            List<string> nkeys = new List<string>();
            for (int k = 1; k < keys.Count; k++)
            {
                tmpkk = "";
                temp = "";
                temp = keys[k];
                for (int m = 0; m < 8; m++) // perm matrix to 48 bits
                {
                    for (int j = 0; j < 6; j++)
                    {
                        tmpkk = tmpkk + temp[PC_2[m, j] - 1];
                    }
                }

                nkeys.Add(tmpkk);
            }


            //premutation by IP for plain text
            string ipaddr = "";
            for (int m = 0; m < 8; m++) // replace kol index bl index bly fe el matrix
            {
                for (int j = 0; j < 8; j++)
                {
                    ipaddr = ipaddr + biplain[IP[m, j] - 1];
                }
            }

            List<string> L = new List<string>();
            List<string> R = new List<string>();

            string l = ipaddr.Substring(0, 32); //left
            string r = ipaddr.Substring(32, 32); // right

            L.Add(l);
            R.Add(r);
            string x = "";
            string h = "";

            string ebity = "";
            string exorky = "";
            List<string> sbox = new List<string>();
            //string sb = "";
            string t = "";
            int row = 0;
            int col = 0;
            string tsb = "";
            string pp = "";
            string lf = "";

            for (int m = 0; m < 16; m++)
            {
                L.Add(r); //left 7t feha el right
                exorky = "";
                ebity = "";
                lf = "";
                pp = "";
                sbox.Clear();
                tsb = "";
                col = 0;
                row = 0;
                t = "";
                for (int j = 0; j < 8; j++) //expantion ll right 5laha 48 bits
                {
                    for (int k = 0; k < 6; k++)
                    {
                        ebity = ebity + r[EB[j, k] - 1];
                    }
                }
                int g = 0;
                while (g < ebity.Length) // plait text xor m3 el key
                {
                    exorky = exorky + (nkeys[m][g] ^ ebity[g]).ToString();
                    g++;
                }
                int z = 0;
                do  //by2smha 6 blocks
                {
                    t = "";
                    for (int y = z; y < 6 + z; y++)
                    {
                        if (6 + z <= exorky.Length)
                            t = t + exorky[y];
                    }

                    sbox.Add(t);
                    z = z + 6;
                } while (z < exorky.Length);
               
                t = "";
                int sb = 0;
                for (int s = 0; s < sbox.Count; s++) 
                {
                    t = sbox[s];
                    x = t[0].ToString() + t[5]; //awl index w a5r index (row)
                    h = t[1].ToString() + t[2] + t[3] + t[4]; //elly fe el nos (column )

                    row = Convert.ToInt32(x, 2); 
                    col = Convert.ToInt32(h, 2);
                    switch (s)
                    {
                        case 0:
                            sb = s1[row, col];
                            break;

                        case 1:
                            sb = s2[row, col];
                            break;

                        case 2:
                            sb = s3[row, col];
                            break;

                        case 3:
                            sb = s4[row, col];
                            break;

                        case 4:
                            sb = s5[row, col];
                            break;

                        case 5:
                            sb = s6[row, col];
                            break;

                        case 6:
                            sb = s7[row, col];
                            break;

                        case 7:
                            sb = s8[row, col];
                            break;
                    }

                    tsb = tsb + Convert.ToString(sb, 2).PadLeft(4, '0');
                }

                x = "";
                h = "";

                for (int k = 0; k < 8; k++) //by7wlha l 32 bits
                {
                    for (int j = 0; j < 4; j++)
                    {
                        pp = pp + tsb[P[k, j] - 1];
                    }
                }

                for (int k = 0; k < pp.Length; k++) // r0 xor l0 
                {
                    lf = lf + (pp[k] ^ l[k]).ToString();
                }

                r = lf;  // swap
                l = L[m + 1];
                R.Add(r);
            }
            for (int y = 0; y < 8; y++) { }
            string r16l16 = R[16] + L[16]; // conctenation 
            string ciphertxt = "";
            for (int m = 0; m < 8; m++)  // byd5lha 3la el inverse matrix
            {
                for (int j = 0; j < 8; j++)
                {
                    ciphertxt += r16l16[IP_1[m, j] - 1];
                }
            }
            string ciphtxt = "0x" + Convert.ToInt64(ciphertxt, 2).ToString("X");

            return ciphtxt;
        }
    }
}