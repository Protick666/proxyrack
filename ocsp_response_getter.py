lst = ['Jefferson Viana Fonseca Abreu',
'Raghav Agrawal',
'Arwa Ebrahim Alebrahim',
'Abdul Haddi Amjad',
'Adrian Louis Baron-Hyppolite',
'Tapan Bhatnagar',
'Huai-Che Chang',
'Samruddhi Santosh Chavan',
'Yi-Han Chen',
'Daniel Juzer Chiba',
'Hsin-Yu Chien',
'TingHung Chiu',
'Jason Anthony Cusati',
'Jiongyu Dai',
'Pradyumna Upendra Dasu',
'Shano Atwood Ezzell Jr',
'Azad Fazal',
'Tanvi Garg',
'Aditya Rajendra Gawali',
'Elsa Gonzalez-Aguilar',
'Rithvik Gottimukkala',
'Abdulmaged Karama Ba Gubair',
'Xiao Guo',
'Neil Alexander Gutkin',
'Alicia Harman',
'Luke Li Jordan',
'Vivek Sanjay Joshi',
'Ravalika Karnati',
'Tarun Rao Keshabhoina',
'Jong Heon Kim',
'Pavan Kumar Konatham',
'Shambhavi Anil Kuthe',
'Chris Lattman',
'Cho Ting Lee',
'Shaoyu Li',
'Jaswanth Sai Reddy Mallu',
'Luke Edward Minton',
'Mohamed Husain Noor Mohamed',
'Pavan Kumar Mulagalapati',
'Rushi Varun Munipalle',
'Usama Munir',
'Rohan Avinash Muthukumar',
'Mihir Lahu Palyekar',
'Promit Panja',
'Poornima Athikari Prasanth',
'Vikas Krishnan Radhakrishnan',
'Rishi Ranjan',
'Amartya Ravi',
'Jonathan Erik Roof',
'Christian Ross',
'Aseem Sangwan',
'Aditya Sathish',
'Rohit Pushkaraj Sathye',
'Goutham Chandramouli Seetharam',
'Prateek Sethi',
'Jaidev Shastri',
'Jeffrey Francis Smith',
'Alex Tsai',
'Justin Vita',
'Yumin Wang',
'Ethan Weaver',
'Yi Wei',
'Chengpei Wu',
'Tinghui Wu',
'Fangzheng Zhang',
'Zheyu Zha']

a = 1

paper_to_topic = {
        21: 1,
        22: 1,
        0: 2,
        1: 2,
        2: 2,
        3: 2,
        13: 3,
        14: 3,
        15: 3,
        16: 3,
        17: 4,
        18: 4,
        19: 4,
        20: 4,
        12: 5,
        11: 5,
        10: 6,
        4: 7,
        5: 7,
        6: 7,
        7: 7,
        8: 7,
        9: 7
    }

def init():
    import xlsxwriter

    papers = 23
    from collections import defaultdict
    paper_to_student_count = defaultdict(lambda: 0)
    paper_to_student_list = defaultdict(lambda: list())

    def assign_student_paper(student, banned_topic=-1):
        min_ = min([paper_to_student_count[e] for e in range(1, 24)])
        candidate_papers = [e for e in range(1, 24) if paper_to_student_count[e] == min_ and paper_to_topic[e-1] != banned_topic]
        import random
        chosen_index = random.randint(1, len(candidate_papers))
        chosen_paper = candidate_papers[chosen_index - 1]
        paper_to_student_list[chosen_paper].append(student)
        paper_to_student_count[chosen_paper] += 1
        return chosen_paper

    for student in lst:
        chosen_paper = assign_student_paper(student)
        chosen_paper_2 = assign_student_paper(student, banned_topic=paper_to_topic[chosen_paper - 1])
        print(student, paper_to_topic[chosen_paper - 1], paper_to_topic[chosen_paper_2 - 1])

    paper_index_list = [21, 22, 0, 1, 2, 3, 13, 14, 15, 16, 17, 18, 19, 20, 12, 11, 10, 4, 5, 6, 7, 8, 9]

    row = 1

    workbook = xlsxwriter.Workbook('Example2.xlsx')
    worksheet = workbook.add_worksheet()

    for e in paper_index_list:
        print(e, len(paper_to_student_list[e + 1]), paper_to_student_list[e + 1])
        column = 0
        items = [e] + paper_to_student_list[e + 1]

        for e in items:
            worksheet.write(row, column, e)
            column += 1
        row = row + 1
    workbook.close()

    return True


while True:
    try:
        t = init()
        if t:
            break
    except:
        pass


