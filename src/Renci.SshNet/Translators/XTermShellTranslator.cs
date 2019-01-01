using System.Collections.Generic;
using System.Text;

namespace Renci.SshNet.Translators
{
    /// <summary>
    /// 
    /// </summary>
    public class XTermShellTranslator
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="rawContent"></param>
        /// <returns></returns>
        public static string TranslateXTermShellToString(string rawContent)
        {
            var removeNewlines = false;
            List<char> temp = new List<char>();
            StringBuilder tempSb = new StringBuilder();
            StringBuilder sb = new StringBuilder();
            int spacesInARow = 0;
            int previousRow = 0;
            for (int i = 0; i < rawContent.Length; i++)
            {
                if (rawContent[i] == 27)    // ESC char
                {
                    i++;
                    if (i < rawContent.Length && rawContent[i] == '[')
                    {
                        i++;
                        string row = "";
                        bool cursorPlacementSequence = true;
                        while (i < rawContent.Length && rawContent[i] != ';')
                        {
                            if (rawContent[i] == 'H' ||
                               rawContent[i] == 'J' ||
                               rawContent[i] == 'l' ||
                               rawContent[i] == 'm' ||
                               rawContent[i] == 'h')
                            {
                                cursorPlacementSequence = false;
                                break;
                            }
                            row += rawContent[i++];
                        }

                        if (!cursorPlacementSequence)
                        {
                            // advance until right before the next escape char (in theory this shouldn't need to be done)
                            while (i + 1 < rawContent.Length && rawContent[i + 1] != 27)
                                i++;
                            continue;
                        }

                        i++;
                        temp.Clear();
                        while (i < rawContent.Length && rawContent[i] != 'H')
                            temp.Add(rawContent[i++]);
                        int currRow;
                        if (int.TryParse(row, out currRow))
                        {
                            if (previousRow <= currRow)
                            {
                                sb.Append(tempSb);
                                if (temp.Count == 1 && temp[0] == '1' && !removeNewlines)
                                {
                                    // check to see if there's no content between here and the previous newline
                                    string temps = sb.ToString();
                                    int previousNewline = -1;
                                    if ((previousNewline = temps.LastIndexOf('\n')) >= 0)
                                    {
                                        string x = temps.Substring(previousNewline);
                                        if (string.IsNullOrWhiteSpace(x))
                                        {
                                            sb.Remove(previousNewline, x.Length);
                                        }
                                    }
                                    else
                                    {
                                        if (string.IsNullOrWhiteSpace(temps))
                                        {
                                            sb.Clear();
                                        }
                                    }
                                    if (sb.Length > 0 && sb[sb.Length - 1] != '\n')
                                        sb.Append("\n");
                                }
                            }
                            else
                            {
                                string temps = sb.ToString();
                                int previousNewline = -1;
                                if ((previousNewline = temps.LastIndexOf('\n')) >= 0)
                                {
                                    string x = temps.Substring(previousNewline);
                                    if (string.IsNullOrWhiteSpace(x))
                                    {
                                        sb.Remove(previousNewline, x.Length);
                                    }
                                }
                            }
                            previousRow = currRow;
                        }
                        tempSb.Clear();
                    }
                    else if (i < rawContent.Length && rawContent[i] == ']')
                    {
                        // Remove all content until '\a'
                        while (i < rawContent.Length && rawContent[i] != '\a')
                            i++;
                        continue;
                    }
                }
                else
                {
                    if (char.IsWhiteSpace(rawContent[i]))
                    {
                        spacesInARow++;
                    }
                    else
                    {
                        spacesInARow = 0;
                    }
                    tempSb.Append(rawContent[i]);
                }
            }
            if (tempSb.Length > 0)
            {
                if (!string.IsNullOrWhiteSpace(tempSb.ToString()))
                    sb.Append(tempSb.ToString());
            }

            string ret = sb.ToString();
            if (string.IsNullOrWhiteSpace(ret))
                return string.Empty;
            return ret;
        }
    }
}
