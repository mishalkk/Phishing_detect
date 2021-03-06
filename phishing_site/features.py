from fun import *
from fun import read_file
import posixpath
import csv


def attributes():
    """Output file attributes."""
    _lexical = [
    'dot_url', 'hyphe_url', 'underline_url', 'bar_url', 'question_url',
    'equal_url', 'arroba_url', 'ampersand_url', 'exclamation_url',
    'blank_url', 'til_url', 'comma_url', 'plus_url', 'asterisk_url', 'hashtag_url',
    'money_sign_url', 'percentage_url', 'count_tld_url', 'len_url', 'dot_host',
    'hyphe_host', 'underline_host', 'bar_host', 'question_host', 'equal_host',
    'arroba_host', 'ampersand_host', 'exclamation_host', 'blank_host', 'til_host',
    'comma_host', 'plus_host', 'asterisk_host', 'hashtag_host', 'money_sign_host',
    'percentage_host', 'vowels_host', 'len_host', 'ip_exist', 'server_client',
    'dot_path', 'hyphe_path', 'underline_path', 'bar_path', 'question_path',
    'equal_path', 'arroba_path', 'ampersand_path', 'exclamation_path',
    'blank_path', 'til_path', 'comma_path', 'plus_path', 'asterisk_path',
    'hashtag_path', 'money_sign_path', 'percentage_path', 'len_path', 'dot_file',
    'hyphe_file', 'underline_file', 'bar_file', 'question_file', 'equal_file',
    'arroba_file', 'ampersand_file', 'exclamation_file', 'blank_file',
    'til_file', 'comma_file', 'plus_file', 'asterisk_file', 'hashtag_file',
    'money_sign_file', 'percentage_file', 'len_file', 'dot_params',
    'hyphe_params', 'underline_params', 'bar_params', 'question_params',
    'equal_params', 'arroba_params', 'ampersand_params', 'exclamation_params',
    'blank_params', 'til_params', 'comma_params', 'plus_params', 'asterisk_params',
    'hashtag_params', 'money_sign_params', 'percentage_params', 'len_params',
    'tld_params', 'number_params', 'email_exist'
    ]

                # _blacklist = [blacklist_url, blacklist_ip, blacklist_domain]

    _host = ['ptr', 'activation_time',
                'expiration_time', 'count_ip', 'count_ns', 'count_mx', 'ttl']

    

    list_attributes = []
    list_attributes.extend(_lexical)
    #list_attributes.extend(blacklist)
    list_attributes.extend(_host)
    list_attributes.extend(['phishing'])

    return list_attributes


def single(url):
    with open('sample.csv', "w",newline='') as output:
        writer = csv.writer(output)
        writer.writerow([url])
        return

def main2(urls, dataset,label):
    with open(dataset, "w") as output:
        writer = csv.writer(output)
        writer.writerow(attributes())
        count_url = 0
        for url in read_file(urls)[0:1]:
            print(url)
            count_url = count_url + 1
            dict_url = start_url(url)

            """LEXICAL"""
            # URL
            dot_url = str(count(dict_url['url'], '.'))
            hyphe_url = str(count(dict_url['url'], '-'))
            underline_url = str(count(dict_url['url'], '_'))
            bar_url = str(count(dict_url['url'], '/'))
            question_url = str(count(dict_url['url'], '?'))
            equal_url = str(count(dict_url['url'], '='))
            arroba_url = str(count(dict_url['url'], '@'))
            ampersand_url = str(count(dict_url['url'], '&'))
            exclamation_url = str(count(dict_url['url'], '!'))
            blank_url = str(count(dict_url['url'], ' '))
            til_url = str(count(dict_url['url'], '~'))
            comma_url = str(count(dict_url['url'], ','))
            plus_url = str(count(dict_url['url'], '+'))
            asterisk_url = str(count(dict_url['url'], '*'))
            hashtag_url = str(count(dict_url['url'], '#'))
            money_sign_url = str(count(dict_url['url'], '$'))
            percentage_url = str(count(dict_url['url'], '%'))
            len_url = str(length(dict_url['url']))
            email_exist = str(valid_email(dict_url['url']))
            count_tld_url = str(count_tld(dict_url['url']))
            # DOMAIN
            dot_host = str(count(dict_url['host'], '.'))
            hyphe_host = str(count(dict_url['host'], '-'))
            underline_host = str(count(dict_url['host'], '_'))
            bar_host = str(count(dict_url['host'], '/'))
            question_host = str(count(dict_url['host'], '?'))
            equal_host = str(count(dict_url['host'], '='))
            arroba_host = str(count(dict_url['host'], '@'))
            ampersand_host = str(count(dict_url['host'], '&'))
            exclamation_host = str(count(dict_url['host'], '!'))
            blank_host = str(count(dict_url['host'], ' '))
            til_host = str(count(dict_url['host'], '~'))
            comma_host = str(count(dict_url['host'], ','))
            plus_host = str(count(dict_url['host'], '+'))
            asterisk_host = str(count(dict_url['host'], '*'))
            hashtag_host = str(count(dict_url['host'], '#'))
            money_sign_host = str(count(dict_url['host'], '$'))
            percentage_host = str(count(dict_url['host'], '%'))
            vowels_host = str(count_vowels(dict_url['host']))
            len_host = str(length(dict_url['host']))
            ip_exist = str(valid_ip(dict_url['host']))
            server_client = str(check_word_server_client(dict_url['host']))
            # DIRECTORY
            if dict_url['path']:
                dot_path = str(count(dict_url['path'], '.'))
                hyphe_path = str(count(dict_url['path'], '-'))
                underline_path = str(count(dict_url['path'], '_'))
                bar_path = str(count(dict_url['path'], '/'))
                question_path = str(count(dict_url['path'], '?'))
                equal_path = str(count(dict_url['path'], '='))
                arroba_path = str(count(dict_url['path'], '@'))
                ampersand_path = str(count(dict_url['path'], '&'))
                exclamation_path = str(count(dict_url['path'], '!'))
                blank_path = str(count(dict_url['path'], ' '))
                til_path = str(count(dict_url['path'], '~'))
                comma_path = str(count(dict_url['path'], ','))
                plus_path = str(count(dict_url['path'], '+'))
                asterisk_path = str(count(dict_url['path'], '*'))
                hashtag_path = str(count(dict_url['path'], '#'))
                money_sign_path = str(count(dict_url['path'], '$'))
                percentage_path = str(count(dict_url['path'], '%'))
                len_path = str(length(dict_url['path']))
            else:
                dot_path = '?'
                hyphe_path = '?'
                underline_path = '?'
                bar_path = '?'
                question_path = '?'
                equal_path = '?'
                arroba_path = '?'
                ampersand_path = '?'
                exclamation_path = '?'
                blank_path = '?'
                til_path = '?'
                comma_path = '?'
                plus_path = '?'
                asterisk_path = '?'
                hashtag_path = '?'
                money_sign_path = '?'
                percentage_path = '?'
                len_path = '?'
            # FILE
            if dict_url['path']:
                dot_file = str(count(posixpath.basename(dict_url['path']), '.'))
                hyphe_file = str(count(posixpath.basename(dict_url['path']), '-'))
                underline_file = str(
                    count(posixpath.basename(dict_url['path']), '_'))
                bar_file = str(count(posixpath.basename(dict_url['path']), '/'))
                question_file = str(
                    count(posixpath.basename(dict_url['path']), '?'))
                equal_file = str(count(posixpath.basename(dict_url['path']), '='))
                arroba_file = str(count(posixpath.basename(dict_url['path']), '@'))
                ampersand_file = str(
                    count(posixpath.basename(dict_url['path']), '&'))
                exclamation_file = str(
                    count(posixpath.basename(dict_url['path']), '!'))
                blank_file = str(count(posixpath.basename(dict_url['path']), ' '))
                til_file = str(count(posixpath.basename(dict_url['path']), '~'))
                comma_file = str(count(posixpath.basename(dict_url['path']), ','))
                plus_file = str(count(posixpath.basename(dict_url['path']), '+'))
                asterisk_file = str(
                    count(posixpath.basename(dict_url['path']), '*'))
                hashtag_file = str(
                    count(posixpath.basename(dict_url['path']), '#'))
                money_sign_file = str(
                    count(posixpath.basename(dict_url['path']), '$'))
                percentage_file = str(
                    count(posixpath.basename(dict_url['path']), '%'))
                len_file = str(length(posixpath.basename(dict_url['path'])))
                extension = str(extract_extension(
                    posixpath.basename(dict_url['path'])))
            else:
                dot_file = '?'
                hyphe_file = '?'
                underline_file = '?'
                bar_file = '?'
                question_file = '?'
                equal_file = '?'
                arroba_file = '?'
                ampersand_file = '?'
                exclamation_file = '?'
                blank_file = '?'
                til_file = '?'
                comma_file = '?'
                plus_file = '?'
                asterisk_file = '?'
                hashtag_file = '?'
                money_sign_file = '?'
                percentage_file = '?'
                len_file = '?'
                extension = '?'
            # PARAMETERS
            if dict_url['query']:
                dot_params = str(count(dict_url['query'], '.'))
                hyphe_params = str(count(dict_url['query'], '-'))
                underline_params = str(count(dict_url['query'], '_'))
                bar_params = str(count(dict_url['query'], '/'))
                question_params = str(count(dict_url['query'], '?'))
                equal_params = str(count(dict_url['query'], '='))
                arroba_params = str(count(dict_url['query'], '@'))
                ampersand_params = str(count(dict_url['query'], '&'))
                exclamation_params = str(count(dict_url['query'], '!'))
                blank_params = str(count(dict_url['query'], ' '))
                til_params = str(count(dict_url['query'], '~'))
                comma_params = str(count(dict_url['query'], ','))
                plus_params = str(count(dict_url['query'], '+'))
                asterisk_params = str(count(dict_url['query'], '*'))
                hashtag_params = str(count(dict_url['query'], '#'))
                money_sign_params = str(count(dict_url['query'], '$'))
                percentage_params = str(count(dict_url['query'], '%'))
                len_params = str(length(dict_url['query']))
                tld_params = str(check_tld(dict_url['query']))
                number_params = str(count_params(dict_url['query']))
            else:
                dot_params = '?'
                hyphe_params = '?'
                underline_params = '?'
                bar_params = '?'
                question_params = '?'
                equal_params = '?'
                arroba_params = '?'
                ampersand_params = '?'
                exclamation_params = '?'
                blank_params = '?'
                til_params = '?'
                comma_params = '?'
                plus_params = '?'
                asterisk_params = '?'
                hashtag_params = '?'
                money_sign_params = '?'
                percentage_params = '?'
                len_params = '?'
                tld_params = '?'
                number_params = '?'

            
            time_domain = str(check_time_response(dict_url['protocol'] + '://' + dict_url['host']))
           
            ptr = str(get_ptr(dict_url))
            activation_time = str(time_activation_domain(dict_url))
            expiration_time = str(expiration_date_register(dict_url))
            count_ip = str(count_ips(dict_url))
            count_ns = str(count_name_servers(dict_url))
            count_mx = str(count_mx_servers(dict_url))
            ttl = str(extract_ttl(dict_url))

            """OTHERS"""
            ssl = str(check_ssl('https://' + dict_url['url']))
            count_redirect = str(count_redirects(
                dict_url['protocol'] + '://' + dict_url['url']))
            google_url = str(google_search(dict_url['url']))
            google_domain = str(google_search(dict_url['host']))
            shortener = str(check_shortener(dict_url))

            _lexical = [
                dot_url, hyphe_url, underline_url, bar_url, question_url,
                equal_url, arroba_url, ampersand_url, exclamation_url,
                blank_url, til_url, comma_url, plus_url, asterisk_url, hashtag_url,
                money_sign_url, percentage_url, count_tld_url, len_url, dot_host,
                hyphe_host, underline_host, bar_host, question_host, equal_host,
                arroba_host, ampersand_host, exclamation_host, blank_host, til_host,
                comma_host, plus_host, asterisk_host, hashtag_host, money_sign_host,
                percentage_host, vowels_host, len_host, ip_exist, server_client,
                dot_path, hyphe_path, underline_path, bar_path, question_path,
                equal_path, arroba_path, ampersand_path, exclamation_path,
                blank_path, til_path, comma_path, plus_path, asterisk_path,
                hashtag_path, money_sign_path, percentage_path, len_path, dot_file,
                hyphe_file, underline_file, bar_file, question_file, equal_file,
                arroba_file, ampersand_file, exclamation_file, blank_file,
                til_file, comma_file, plus_file, asterisk_file, hashtag_file,
                money_sign_file, percentage_file, len_file, dot_params,
                hyphe_params, underline_params, bar_params, question_params,
                equal_params, arroba_params, ampersand_params, exclamation_params,
                blank_params, til_params, comma_params, plus_params, asterisk_params,
                hashtag_params, money_sign_params, percentage_params, len_params,
                tld_params, number_params, email_exist
            ]
            _lexical=[-1 if x=='?' else x for x in _lexical]

            # _blacklist = [blacklist_url, blacklist_ip, blacklist_domain]

            _host = [ptr, activation_time,
                     expiration_time, count_ip, count_ns, count_mx, ttl]

            
            _host=[-1 if x=='?' else x for x in _host]
            

            result = []
            result.extend(_lexical)
            # result.extend(_blacklist)
            result.extend(_host)
            
            result.extend([label])

            writer.writerow(result)

def main(urls, dataset,label):
    with open(dataset, "w") as output:
        writer = csv.writer(output)
        writer.writerow(attributes())
        count_url = 0
        for url in read_file(urls):
            print(url)
            count_url = count_url + 1
            dict_url = start_url(url)

            """LEXICAL"""
            # URL
            dot_url = str(count(dict_url['url'], '.'))
            hyphe_url = str(count(dict_url['url'], '-'))
            underline_url = str(count(dict_url['url'], '_'))
            bar_url = str(count(dict_url['url'], '/'))
            question_url = str(count(dict_url['url'], '?'))
            equal_url = str(count(dict_url['url'], '='))
            arroba_url = str(count(dict_url['url'], '@'))
            ampersand_url = str(count(dict_url['url'], '&'))
            exclamation_url = str(count(dict_url['url'], '!'))
            blank_url = str(count(dict_url['url'], ' '))
            til_url = str(count(dict_url['url'], '~'))
            comma_url = str(count(dict_url['url'], ','))
            plus_url = str(count(dict_url['url'], '+'))
            asterisk_url = str(count(dict_url['url'], '*'))
            hashtag_url = str(count(dict_url['url'], '#'))
            money_sign_url = str(count(dict_url['url'], '$'))
            percentage_url = str(count(dict_url['url'], '%'))
            len_url = str(length(dict_url['url']))
            email_exist = str(valid_email(dict_url['url']))
            count_tld_url = str(count_tld(dict_url['url']))
            # DOMAIN
            dot_host = str(count(dict_url['host'], '.'))
            hyphe_host = str(count(dict_url['host'], '-'))
            underline_host = str(count(dict_url['host'], '_'))
            bar_host = str(count(dict_url['host'], '/'))
            question_host = str(count(dict_url['host'], '?'))
            equal_host = str(count(dict_url['host'], '='))
            arroba_host = str(count(dict_url['host'], '@'))
            ampersand_host = str(count(dict_url['host'], '&'))
            exclamation_host = str(count(dict_url['host'], '!'))
            blank_host = str(count(dict_url['host'], ' '))
            til_host = str(count(dict_url['host'], '~'))
            comma_host = str(count(dict_url['host'], ','))
            plus_host = str(count(dict_url['host'], '+'))
            asterisk_host = str(count(dict_url['host'], '*'))
            hashtag_host = str(count(dict_url['host'], '#'))
            money_sign_host = str(count(dict_url['host'], '$'))
            percentage_host = str(count(dict_url['host'], '%'))
            vowels_host = str(count_vowels(dict_url['host']))
            len_host = str(length(dict_url['host']))
            ip_exist = str(valid_ip(dict_url['host']))
            server_client = str(check_word_server_client(dict_url['host']))
            # DIRECTORY
            if dict_url['path']:
                dot_path = str(count(dict_url['path'], '.'))
                hyphe_path = str(count(dict_url['path'], '-'))
                underline_path = str(count(dict_url['path'], '_'))
                bar_path = str(count(dict_url['path'], '/'))
                question_path = str(count(dict_url['path'], '?'))
                equal_path = str(count(dict_url['path'], '='))
                arroba_path = str(count(dict_url['path'], '@'))
                ampersand_path = str(count(dict_url['path'], '&'))
                exclamation_path = str(count(dict_url['path'], '!'))
                blank_path = str(count(dict_url['path'], ' '))
                til_path = str(count(dict_url['path'], '~'))
                comma_path = str(count(dict_url['path'], ','))
                plus_path = str(count(dict_url['path'], '+'))
                asterisk_path = str(count(dict_url['path'], '*'))
                hashtag_path = str(count(dict_url['path'], '#'))
                money_sign_path = str(count(dict_url['path'], '$'))
                percentage_path = str(count(dict_url['path'], '%'))
                len_path = str(length(dict_url['path']))
            else:
                dot_path = '?'
                hyphe_path = '?'
                underline_path = '?'
                bar_path = '?'
                question_path = '?'
                equal_path = '?'
                arroba_path = '?'
                ampersand_path = '?'
                exclamation_path = '?'
                blank_path = '?'
                til_path = '?'
                comma_path = '?'
                plus_path = '?'
                asterisk_path = '?'
                hashtag_path = '?'
                money_sign_path = '?'
                percentage_path = '?'
                len_path = '?'
            # FILE
            if dict_url['path']:
                dot_file = str(count(posixpath.basename(dict_url['path']), '.'))
                hyphe_file = str(count(posixpath.basename(dict_url['path']), '-'))
                underline_file = str(
                    count(posixpath.basename(dict_url['path']), '_'))
                bar_file = str(count(posixpath.basename(dict_url['path']), '/'))
                question_file = str(
                    count(posixpath.basename(dict_url['path']), '?'))
                equal_file = str(count(posixpath.basename(dict_url['path']), '='))
                arroba_file = str(count(posixpath.basename(dict_url['path']), '@'))
                ampersand_file = str(
                    count(posixpath.basename(dict_url['path']), '&'))
                exclamation_file = str(
                    count(posixpath.basename(dict_url['path']), '!'))
                blank_file = str(count(posixpath.basename(dict_url['path']), ' '))
                til_file = str(count(posixpath.basename(dict_url['path']), '~'))
                comma_file = str(count(posixpath.basename(dict_url['path']), ','))
                plus_file = str(count(posixpath.basename(dict_url['path']), '+'))
                asterisk_file = str(
                    count(posixpath.basename(dict_url['path']), '*'))
                hashtag_file = str(
                    count(posixpath.basename(dict_url['path']), '#'))
                money_sign_file = str(
                    count(posixpath.basename(dict_url['path']), '$'))
                percentage_file = str(
                    count(posixpath.basename(dict_url['path']), '%'))
                len_file = str(length(posixpath.basename(dict_url['path'])))
                extension = str(extract_extension(
                    posixpath.basename(dict_url['path'])))
            else:
                dot_file = '?'
                hyphe_file = '?'
                underline_file = '?'
                bar_file = '?'
                question_file = '?'
                equal_file = '?'
                arroba_file = '?'
                ampersand_file = '?'
                exclamation_file = '?'
                blank_file = '?'
                til_file = '?'
                comma_file = '?'
                plus_file = '?'
                asterisk_file = '?'
                hashtag_file = '?'
                money_sign_file = '?'
                percentage_file = '?'
                len_file = '?'
                extension = '?'
            # PARAMETERS
            if dict_url['query']:
                dot_params = str(count(dict_url['query'], '.'))
                hyphe_params = str(count(dict_url['query'], '-'))
                underline_params = str(count(dict_url['query'], '_'))
                bar_params = str(count(dict_url['query'], '/'))
                question_params = str(count(dict_url['query'], '?'))
                equal_params = str(count(dict_url['query'], '='))
                arroba_params = str(count(dict_url['query'], '@'))
                ampersand_params = str(count(dict_url['query'], '&'))
                exclamation_params = str(count(dict_url['query'], '!'))
                blank_params = str(count(dict_url['query'], ' '))
                til_params = str(count(dict_url['query'], '~'))
                comma_params = str(count(dict_url['query'], ','))
                plus_params = str(count(dict_url['query'], '+'))
                asterisk_params = str(count(dict_url['query'], '*'))
                hashtag_params = str(count(dict_url['query'], '#'))
                money_sign_params = str(count(dict_url['query'], '$'))
                percentage_params = str(count(dict_url['query'], '%'))
                len_params = str(length(dict_url['query']))
                tld_params = str(check_tld(dict_url['query']))
                number_params = str(count_params(dict_url['query']))
            else:
                dot_params = '?'
                hyphe_params = '?'
                underline_params = '?'
                bar_params = '?'
                question_params = '?'
                equal_params = '?'
                arroba_params = '?'
                ampersand_params = '?'
                exclamation_params = '?'
                blank_params = '?'
                til_params = '?'
                comma_params = '?'
                plus_params = '?'
                asterisk_params = '?'
                hashtag_params = '?'
                money_sign_params = '?'
                percentage_params = '?'
                len_params = '?'
                tld_params = '?'
                number_params = '?'

            
            time_domain = str(check_time_response(dict_url['protocol'] + '://' + dict_url['host']))
           
            ptr = str(get_ptr(dict_url))
            activation_time = str(time_activation_domain(dict_url))
            expiration_time = str(expiration_date_register(dict_url))
            count_ip = str(count_ips(dict_url))
            count_ns = str(count_name_servers(dict_url))
            count_mx = str(count_mx_servers(dict_url))
            ttl = str(extract_ttl(dict_url))

            """OTHERS"""
            ssl = str(check_ssl('https://' + dict_url['url']))
            count_redirect = str(count_redirects(
                dict_url['protocol'] + '://' + dict_url['url']))
            google_url = str(google_search(dict_url['url']))
            google_domain = str(google_search(dict_url['host']))
            shortener = str(check_shortener(dict_url))

            _lexical = [
                dot_url, hyphe_url, underline_url, bar_url, question_url,
                equal_url, arroba_url, ampersand_url, exclamation_url,
                blank_url, til_url, comma_url, plus_url, asterisk_url, hashtag_url,
                money_sign_url, percentage_url, count_tld_url, len_url, dot_host,
                hyphe_host, underline_host, bar_host, question_host, equal_host,
                arroba_host, ampersand_host, exclamation_host, blank_host, til_host,
                comma_host, plus_host, asterisk_host, hashtag_host, money_sign_host,
                percentage_host, vowels_host, len_host, ip_exist, server_client,
                dot_path, hyphe_path, underline_path, bar_path, question_path,
                equal_path, arroba_path, ampersand_path, exclamation_path,
                blank_path, til_path, comma_path, plus_path, asterisk_path,
                hashtag_path, money_sign_path, percentage_path, len_path, dot_file,
                hyphe_file, underline_file, bar_file, question_file, equal_file,
                arroba_file, ampersand_file, exclamation_file, blank_file,
                til_file, comma_file, plus_file, asterisk_file, hashtag_file,
                money_sign_file, percentage_file, len_file, dot_params,
                hyphe_params, underline_params, bar_params, question_params,
                equal_params, arroba_params, ampersand_params, exclamation_params,
                blank_params, til_params, comma_params, plus_params, asterisk_params,
                hashtag_params, money_sign_params, percentage_params, len_params,
                tld_params, number_params, email_exist
            ]
            _lexical=[-1 if x=='?' else x for x in _lexical]

            # _blacklist = [blacklist_url, blacklist_ip, blacklist_domain]

            _host = [ptr, activation_time,
                     expiration_time, count_ip, count_ns, count_mx, ttl]

            
            _host=[-1 if x=='?' else x for x in _host]
            

            result = []
            result.extend(_lexical)
            # result.extend(_blacklist)
            result.extend(_host)
            
            result.extend([label])

            writer.writerow(result)


if __name__=="__main__":
    main('phish.csv','result.csv',1)            